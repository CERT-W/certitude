# CERTitude: the seeker of IOC
# Copyright (c) 2016 CERT-W

# Contact: cert@wavestone.com
# Contributors: @iansus, @nervous, @fschwebel

# CERTitude is under licence GPL-2.0:
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

KEY_FILE="server.pem.key"
CSR_FILE="server.pem.csr"
CER_FILE="server.pem.cer"

openssl genrsa -f4 -out "$KEY_FILE" 4096
openssl req -new -key "$KEY_FILE" -out "$CSR_FILE" -sha256
openssl x509 -req -signkey "$KEY_FILE" -in "$CSR_FILE" -days 365 -out "$CER_FILE" -sha256
del "$CSR_FILE"