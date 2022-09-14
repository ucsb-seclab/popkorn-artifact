import re
import ipdb


def extract_drivername(name):
    if match := re.fullmatch('[0-9a-fA-F]{32}_(.*)\.sys', name):
        name = match.group(1) + '.sys'
    if match := re.fullmatch('[0-9a-fA-F]{64}_(.*)\.sys', name):
        name = match.group(1) + '.sys'
    if match := re.fullmatch('(.*)_[0-9a-fA-F]{32}\.sys', name):
        name = match.group(1) + '.sys'
    if match := re.fullmatch('(.*)_[0-9a-fA-F]{64}\.sys', name):
        name = match.group(1) + '.sys'

    return name


# manually added
KNOWN_DUPLICATES = {
    'IAMT03.sys': 'IAMTXPE.sys',
    'IAMTVE.sys': 'IAMTV.sys',
    'L8042Mou,1.sys': 'L8042Mount.sys',
    'Ltn_stk7070p.sys': 'Ltn_stk7770p.sys',
    'athw10x.sys': 'athwbx.sys',
    'atikmdag.sys': 'atikmpag.sys',
    'iqvw64e.sys': 'iqvw.sys',
    'qd162.sys': 'qd160.sys',
    'qd252.sys': 'qd160.sys',
    'qd260.sys': 'qd160.sys',
    'qd262.sys': 'qd160.sys',
    'rimmptsk.sys': 'rimmp.sys',
    'rimsptsk.sys': 'rimmp.sys',
    'rixdptsk.sys': 'rimmp.sys',
    'rtkiow8.sys': 'rtkio.sys',
    'snxpserx.sys': 'snxpsamd.sys',
}
def fully_normalized_drivername(name):
    name = extract_drivername(name)
    name = re.sub('(.*)(x86|x64|i386|2k)\.sys$', lambda match: match.groups()[0] + '.sys', name, count=1)
    name = re.sub('(.*)(86|32|64)\.sys$', lambda match: match.groups()[0] + '.sys', name, count=1)
    name = re.sub('(.*)([xX][pP]|[nN][tT]|[lL][pP]|\_)\.sys$', lambda match: match.groups()[0] + '.sys', name, count=1)
    name = re.sub('Xeno[XV7]a?\.sys$', lambda match: 'Xeno.sys', name, count=1)
    name = KNOWN_DUPLICATES.get(name, name)
    name = name.replace(',', '_')
    name = name.lower()
    return name

