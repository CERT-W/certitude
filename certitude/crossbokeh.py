import pandas as pd
import io

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from config import CERTITUDE_DATABASE, LISTEN_ADDRESS, LISTEN_PORT

from helpers.queue_models import Task
from helpers.results_models import Result, IOCDetection
from helpers.misc_models import ConfigurationProfile, XMLIOC, Batch
import base64

import components.scanner.openioc.openiocparser as openiocparser
import xml.etree.ElementTree as ET

from bokeh.layouts import row, widgetbox, layout
from bokeh.models import Select, Slider, DataTable, TableColumn, ColumnDataSource

from bokeh.models import ColumnDataSource, BoxSelectTool, ResetTool, Div, HTMLTemplateFormatter
from bokeh.plotting import curdoc, figure

try:
    args = curdoc().session_context.request.arguments
    batch_id = int(args.get('batchid')[0])
except:
    print 'none specified - setting batch id to 1..'
    batch_id = 1

def getInfosFromXML(content):
    c = base64.b64decode(content)
    r = {'guids': {}, 'totalguids': 0}

    xml = ET.fromstring(c)
    openiocparser.removeNS(xml)

    for indic in xml.iter('IndicatorItem'):
        guid = indic.attrib['id']

        context = indic.findall('Context')[0]
        search = context.attrib['search']

        content = indic.findall('Content')[0]
        value = content.text

        r['guids'][guid] = {'search': search, 'value': value}
        r['totalguids'] += 1

    return r

def getDataframeFromBatchid(batchid):
    engine = create_engine(CERTITUDE_DATABASE, echo=False)
    dbsession = sessionmaker(bind=engine)()

    columns = ['HostId','HostnameIP' , 'Lookup:Success' , 'Lookup:IOCScanned' , 'Lookup:HashScanned', 'Lookup:Subnet' , 'Malware', 'Compromise']
    coldata = []

    batch = dbsession.query(Batch).filter_by(id=batchid).first()
    if batch is None:
        raise Exception('No batch found')

    # Get all IOCs
    cp = dbsession.query(ConfigurationProfile).filter_by(id=batch.configuration_profile_id).first()

    if cp.ioc_list == '':
        ioc_list = []
    else:
        ioc_list = [int(e) for e in cp.ioc_list.split(',')]

    iocs = dbsession.query(XMLIOC).filter(XMLIOC.id.in_(ioc_list)).all()

    # Complete first line & assoc ioc.id => ioc
    all_iocs = {}
    for ioc in iocs:
        all_iocs[ioc.id] = ioc
        columns.append('%s' % ioc.name)


    all_tasks_results = dbsession.query(Task, Result).filter(Task.batch_id == batchid).join(Result,
                                                                                            Task.id == Result.tache_id).all()

    # Get total indicator items / IOC
    total_by_ioc = {}
    for ioc in iocs:
        infos = getInfosFromXML(ioc.xml_content)
        total_by_ioc[ioc.id] = infos['totalguids']

    for task, result in all_tasks_results:
        ioc_detections = dbsession.query(IOCDetection).filter_by(result_id=result.id).all()
        result_for_host = {e: 0 for e in ioc_list}

        # Sum IOC detections
        for ioc_detection in ioc_detections:
            result_for_host[ioc_detection.xmlioc_id] += 1

        # Compute n in [0,1] = % of detection
        result_for_host = {id: round(val * 100. / total_by_ioc[id]) / 100 for id, val in result_for_host.items()}

        # Get max
        mval, mid = 0, -1
        for id, val in result_for_host.items():
            if val > mval:
                mval, mid = val, id

        # Complete max compromise
        mname = "None" if mid == -1 else all_iocs[mid].name
        panda_response = ['%d' % result.id, '%s' % task.ip, '%s' % result.smbreachable,
                          '%s' % task.iocscanned, '%s' % task.hashscanned, '%s' % task.commentaire,
                          '%s' % mname, float('%.2f' % mval)]

        # Complete detection / IOC
        for id in all_iocs:
            panda_response.append(float('%.2f' % result_for_host[id]))

        coldata.append(panda_response)
        # df.loc[len(df)] = panda_response

    return pd.DataFrame(coldata, columns = columns)

pandata = getDataframeFromBatchid(batch_id)
pandata.fillna('None', inplace=True)  # just replace missing values with zero

source = ColumnDataSource(pandata)

SIZES = list(range(6, 22, 3))

columns = [
        TableColumn(field="HostnameIP", title="Address", width=450),
        TableColumn(field="Malware", title="Malware"),
        TableColumn(field="Compromise", title="Compromise"),
        TableColumn(field="Lookup:Success", title="Success"),
        TableColumn(field="Lookup:IOCScanned", title="IOCScanned"),
        TableColumn(field="Lookup:HashScanned", title="HashScanned"),
        TableColumn(field="Lookup:Subnet", title="Subnet"),
        TableColumn(field='HostId', title='Result',
                    formatter=HTMLTemplateFormatter(
                    template='<a href="http://%s:%d/host-result/<%%= value %%>" target="_blank">#<%%= value %%></a>' % (LISTEN_ADDRESS, LISTEN_PORT)))

]
data_table = DataTable(source=source, columns=columns, fit_columns=True)

columns = sorted(pandata.columns)
filtered_columns = [c for c in columns if 'Hostname' not in c and 'HostId' not in c]
discrete = [x for x in columns if pandata[x].dtype == object]
continuous = [x for x in columns if x not in discrete]
quantileable = [x for x in continuous if len(pandata[x].unique()) > 1]

def create_figure():
    # args = curdoc().session_context.request.arguments
    # with open('args.txt', 'w') as the_file:
    #     the_file.write(str(curdoc().session_context.request.arguments['batchid']))
    #     the_file.write(str(args))

    df = select_units()

    xs = df[x.value].values
    ys = df[y.value].values
    df['x'] = xs
    df['y'] = ys

    source.data = df.to_dict(orient='list')

    x_title = x.value.title()
    y_title = y.value.title()

    kw = dict()
    if x.value in discrete:
        kw['x_range'] = sorted(set(xs))
    if y.value in discrete:
        kw['y_range'] = sorted(set(ys))
    # kw['title'] = "%s" % (dir(args))
    kw['title'] = "%s vs %s (%i elements)" % (x_title, y_title, len(df))

    # hover = HoverTool(tooltips=[("Address", "@HostnameIP"), ("Malware", "@Malware"), ("Compromise", "@Compromise")])
    p = figure(plot_width=500, plot_height=500, tools=[BoxSelectTool(), ResetTool()], **kw)
    p.xaxis.axis_label = x_title
    p.yaxis.axis_label = y_title

    if x.value in discrete:
        p.xaxis.major_label_orientation = pd.np.pi / 4

        # c = np.where(pandata["Compromise"] > 0, "orange", "grey")
        # sz = np.where(pandata["Compromise"] > 0, 9 * , "grey")

    p.circle(x='x', y='y', source=source, size=15,
            selection_color="orange", alpha=0.8, nonselection_alpha=0.4, selection_alpha=0.6)

    return p


def select_units():
    malware_val = malware.value
    subnet_val = subnet.value

    selected = pandata[
        (pandata.Compromise >= compromise.value)
    ]

    if (malware_val != "All"):
        selected = selected[selected.Malware.str.contains(malware_val) == True]
    if (subnet_val != "All"):
        selected = selected[selected["Lookup:Subnet"].str.contains(subnet_val) == True]

    return selected


def update():
    layout.children[0].children[1] = create_figure()

def update_data():
    df = select_units()
    df['x'] = df[x.value].values
    df['y'] = df[y.value].values

    #source.data.update(ColumnDataSource(data=df).data)
    source.data = df.to_dict(orient='list')
    #source.stream(df.to_dict(orient='index'))


x = Select(title='X-Axis', value='Malware', options=filtered_columns)
y = Select(title='Y-Axis', value='Compromise', options=filtered_columns)
malware = Select(title="Malware", value="All", options=['All'] + list(set(pandata['Malware'])))
subnet = Select(title="Subnet", value="All", options=['All'] + list(set(pandata['Lookup:Subnet'])))
# size = Select(title='Size', value='None', options=['None'] + quantileable)
# color = Select(title='Color', value='None', options=['None'] + quantileable)
compromise = Slider(title="Compromise", value=0.0, start=0.0, end=1.0, step=0.1)

inputs_plot = [x, y]
for input in inputs_plot:
    input.on_change('value', lambda attr, old, new: update())

inputs_data = [malware, compromise, subnet]
for input in inputs_data:
    input.on_change('value', lambda attr, old, new: update_data())

controls = widgetbox([x, y, malware, subnet, compromise], width=200, sizing_mode='fixed')

sizing_mode = 'scale_width'

layout = layout([
    [controls, create_figure()],
    [data_table]
])

curdoc().add_root(layout)
curdoc().title = "Crossfilter"
