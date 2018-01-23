class BubbleChart
  constructor: (data) ->
    @data = data
    @width = 1000
    @height = 600
    @default_radius = 15

    @tooltip = CustomTooltip("my_tooltip", 240)

    # locations the nodes will move towards
    # depending on which view is currently being
    # used
    @center = {x: @width / 2, y: @height / 2}

    # used when setting up force and
    # moving around nodes
    @layout_gravity = -0.01
    @damper = 0.5

    # these will be set in create_nodes and create_vis
    @vis = null
    @force = null
    @circles = null
    @nodes = []

    this.create_nodes()
    this.create_vis()

  # create node objects from original data
  # that will serve as the data behind each
  # bubble in the vis, then add each node
  # to @nodes to be used later
  create_nodes: () =>
    @data.forEach (d, i) =>
      node = {
        id: i
        original: d
        radius: @default_radius
        value: 99
        x: Math.random() * @width
        y: Math.random() * @height
      }
      @nodes.push node

  # create svg at #vis and then
  # create circle representation for each node
  create_vis: () =>
    @vis = d3.select("#vis").append("svg")
      .attr("width", @width)
      .attr("height", @height)
      .attr("id", "svg_vis")

    @circles = @vis.selectAll("circle")
      .data(@nodes, (d) -> d.id)

    # used because we need 'this' in the
    # mouse callbacks
    that = this

    # radius will be set to 0 initially.
    # see transition below
    @circles.enter().append("circle")
      .attr("r", 100)
      .style("fill", (d) => '#cfcfcf')
      .attr("stroke-width", 2)
      .attr("stroke", (d) => '#404040')
      .attr("id", (d) -> "bubble_#{d.id}")
      .attr("opacity", 0)
      .on("mouseover", (d,i) -> that.show_details(d,i,this))
      .on("mouseout", (d,i) -> that.hide_details(d,i,this))

    # Fancy transition to make bubbles appear, ending with the
    # correct radius
    @circles.transition().duration(2000).attr("opacity",1).attr("r", (d) -> d.radius)


  # Charge function that is called for each node.
  # Charge is proportional to the diameter of the
  # circle (which is stored in the radius attribute
  # of the circle's associated data.
  # This is done to allow for accurate collision
  # detection with nodes of different sizes.
  # Charge is negative because we want nodes to
  # repel.
  charge: (d) ->
    if d.radius == 0
      return 0;
    -Math.pow(d.radius, 2)

  # Starts up the force layout with
  # the default values
  start: () =>
    @force = d3.layout.force()
      .nodes(@nodes)
      .size([@width, @height])

    @circles.call(@force.drag)

  # Sets up force layout to display
  # all nodes in one circle.
  display_group_all: () =>
    @hide_labels()
    @force.gravity(@layout_gravity)
      .charge(this.charge)
      .friction(0.9)
      .on "tick", (e) =>
        @circles.each(this.move_towards_center(e.alpha))
          .attr("cx", (d) -> d.x)
          .attr("cy", (d) -> d.y)
    @force.start()

  # Moves all circles towards the @center
  # of the visualization
  move_towards_center: (alpha) =>
    (d) =>
      d.x = d.x + (@center.x - d.x) * (@damper + 0.02) * alpha
      d.y = d.y + (@center.y - d.y) * (@damper + 0.02) * alpha

  get_color_map_achievement: (allValuesArray) =>
    color_map = {}
    for value in allValuesArray
      if value <= -2
        color_map[value] = '#ff0000'
      else if value <= -1
        color_map[value] = '#ff9900'
      else if value <= 0
        color_map[value] = '#ffff00'
      else if value < 2
        color_map[value] = '#00FF00'
      else color_map[value] = '#FF00CC'
    return color_map

  get_color_map_grade: (allValuesArray) =>
    color_map = {}
    for value in allValuesArray
        switch value
          when "*" then color_map[value] = '#FF00CC'
          when "Z" then color_map[value] = '#FF00CC'
          when "A" then color_map[value] = '#00FF00'
          when "B" then color_map[value] = '#00FF00'
          when "C" then color_map[value] = '#FFFF00'
          when "D" then color_map[value] = '#FF0000'
          when "E" then color_map[value] = '#FF0000'
          when "F" then color_map[value] = '#FF0000'
          when "G" then color_map[value] = '#FF0000'
          when "U" then color_map[value] = '#7F0000'
          else color_map[value] = '#4F4F4F'
    return color_map

  get_color_map_lookup_set: (allValuesArray) =>
    baseArray = ["#0000D9","#FF00FF","#FF0033","#FFCC66","#66CC33","#33FFCC","#00A0AA","#FFCCFF","#FF9933","#99FF99","#00BB00","#CCFFCC","#333333","#CCCCCC","#99CCCC","#FF0000"]
    index = 0
    color_map = {}
    for value in allValuesArray
       color_map[value] = baseArray[index]
       index = index + 1
       index = 0 if index >= baseArray.length
    return color_map

  get_type_from_key_name: (keyName) =>
    if /^Achievement/.test(keyName)
      return "VINCENT"
    if /^Grade/.test(keyName)
      return "Grade"
    return "Other"

  get_color_map: (keyName, allValuesArray) =>
    key_type = @get_type_from_key_name(keyName)
    switch key_type
        when "Achievement" then return @get_color_map_achievement(allValuesArray)
        when "Grade" then return @get_color_map_grade(allValuesArray)
        else return @get_color_map_lookup_set(allValuesArray)

  sort: (keyName, allValuesArray) =>
    key_type = @get_type_from_key_name(keyName)
    switch key_type
        when "Achievement" then allValuesArray.sort((a,b) => return Number(a) - Number(b))
        else allValuesArray.sort()

  remove_colors: () =>
    @circles.transition().duration(2000).style("fill","#cfcfcf")
    hide_color_chart()

  color_by: (what_to_color_by) =>
    @what_to_color_by = what_to_color_by
    allValuesArray = @get_distinct_values(what_to_color_by)
    color_mapper = @get_color_map(what_to_color_by, allValuesArray)
    show_color_chart(what_to_color_by, color_mapper)
    @circles.transition().duration(1000).style("fill",(d) => color_mapper[d.original[what_to_color_by]])

  get_distinct_values: (what) =>
    allValues = {}
    @nodes.forEach (d) =>
      value = d.original[what]
      allValues[value] = true
    allValuesArray = []
    for key, value of allValues
      allValuesArray.push(key)
    @sort(what, allValuesArray)
    return allValuesArray

  group_by: (what_to_group_by) =>
    @what_to_group_by = what_to_group_by
    allValuesArray = @get_distinct_values(what_to_group_by)
    numCenters = allValuesArray.length
    @group_centers = {}
    @group_labels = {}
    position = 2
    total_slots = allValuesArray.length + 4
    allValuesArray.forEach (i) =>
      x_position = @width * position / total_slots
      @group_centers[i] = { x: x_position, y : @height /2 }
      @group_labels[i] = x_position
      position = position + 1

    @hide_labels()
    @force.gravity(@layout_gravity)
      .charge(this.charge)
      .friction(0.9)
      .on "tick", (e) =>
        @circles.each(this.move_towards_group_center(e.alpha))
          .attr("cx", (d) -> d.x)
          .attr("cy", (d) -> d.y)
    @force.start()
    @display_labels()

  # move all circles to their associated @group_centers
  move_towards_group_center: (alpha) =>
    (d) =>
      value = d.original[@what_to_group_by]
      target = @group_centers[value]
      d.x = d.x + (target.x - d.x) * (@damper + 0.02) * alpha * 1.1
      d.y = d.y + (target.y - d.y) * (@damper + 0.02) * alpha * 1.1


  # sets the display of bubbles to be separated
  # into each year. Does this by calling move_towards_year
  display_by_group: () =>
    @force.gravity(@layout_gravity)
      .charge(this.charge)
      .friction(0.9)
      .on "tick", (e) =>
        @circles.each(this.move_towards_group(e.alpha))
          .attr("cx", (d) -> d.x)
          .attr("cy", (d) -> d.y)
    @force.start()

    this.display_years()

  # move all circles to their associated @year_centers
  move_towards_group: (alpha) =>
    (d) =>
      target = @group_centers[d.group]
      d.x = d.x + (target.x - d.x) * (@damper + 0.02) * alpha * 1.1
      d.y = d.y + (target.y - d.y) * (@damper + 0.02) * alpha * 1.1

  display_labels: () =>
    label_data = d3.keys(@group_labels)
    labels = @vis.selectAll(".top_labels")
      .data(label_data)

    labels.enter().append("text")
      .attr("class", "top_labels")
      .attr("x", (d) => @group_labels[d] )
      .attr("y", 40)
      .attr("text-anchor", "start")
      .text((d) -> d)

  # Method to hide year titiles
  hide_labels: () =>
    labels = @vis.selectAll(".top_labels").remove()

  show_details: (data, i, element) =>
    d3.select(element).attr("stroke", "black")
    content = ""
    for key, value of data.original
        title = key.substring(key.indexOf(":")+1)
        content += "<span class=\"name\">#{title}:</span><span class=\"value\"> #{value}</span><br/>"
    @tooltip.showTooltip(content,d3.event)

  hide_details: (data, i, element) =>
    d3.select(element).attr("stroke", "#404040")
    @tooltip.hideTooltip()

  use_filters: (filters) =>
    @nodes.forEach (d) =>
       d.radius = @default_radius
       filters.discrete.forEach (filter) =>
         value = d.original[filter.target]
         d.radius = 0 if filter.removeValues[value]?
       @do_filter()

  do_filter: () =>
    @force.start()
    @circles.transition().duration(2000).attr("r", (d) -> d.radius)

root = exports ? this

$ ->
  chart = null

  render_vis = (csv) ->
    render_filters_colors_and_groups csv
    render_chart csv
  render_chart = (csv) ->
    chart = new BubbleChart csv
    chart.start()
    root.display_all()
  root.display_all = () =>
    chart.display_group_all()
  root.group_by = (groupBy) =>
    if groupBy == ''
        chart.display_group_all()
    else
        chart.group_by(groupBy)
  root.color_by = (colorBy) =>
    if colorBy == ''
        chart.remove_colors()
    else
        chart.color_by(colorBy)
  root.use_filters = (filters) =>
    chart.use_filters(filters)
