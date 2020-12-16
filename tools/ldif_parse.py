from ldif import LDIFParser
from io import StringIO
import argparse
import io

attribs_capture = ['uidNumber', 'gidNumber', 'uid',
                   'gid', 'primaryGroupID', 'sAMAccountaName']
dn_group_map = ['UniqueMember', 'memberOf']
uid_group_map = ['member']

def ldif_clean(file_name):
    data = ''
    # This yields the next line, while filtering out everyting except dn: entries
    with open(file_name, 'r') as in_file_stream:
        for line in in_file_stream:

            if line.startswith('#'):
                continue

            elif line == '\n':
                continue

            elif line[0] == ' ':
                continue

            elif line.startswith('dn:'):
                while True:
                    data += line
                    line = in_file_stream.readline()
                    if line == '\n':
                        data += line
                        break
            else:
                while True:
                    # out_file_stream.write(line)
                    line = in_file_stream.readline()
                    if line == '\n':
                        # out_file_stream.write(line)
                        break
    return data


class PureLDIF(LDIFParser):
    def __init__(self, input_file):
        input_stream = StringIO(ldif_clean(input_file))
        LDIFParser.__init__(self, input_stream)
        self.data = {}
        self.map_user_dn = {}
        self.map_group_dn = {}
        self.map_uidNumber_dn = {}
        self.map_gidNumber_dn = {}
        self.parse()
        

    def create_new(self, dn):
        if dn not in self.data:
            self.data[dn] = {'sam': None, 'uidNumber': None, 'gidNumber': None,
                             'member': [], 'memberOf': [], 'objectClass': None,
                             'unixHomeDirectory': None, 'loginShell': None}

    def decode_str_list(self, item):
        # Convert list of bytes into a list of strings
        new_item = []
        for i in item:
            new_item.append(i.decode('utf-8').lower())
        return new_item

    def handle_user(self, dn, entry):
        # ad user, memberOf is a dn
        self.data[dn]['objectClass'] = 'user'
        if 'uidNumber' in entry:
            self.data[dn]['uidNumber'] = entry['uidNumber'][0].decode('utf-8')
            self.map_uidNumber_dn[self.data[dn]['uidNumber']] = dn

        if 'gidNumber' in entry:
            self.data[dn]['gidNumber'] = entry['gidNumber'][0].decode('utf-8')

        sam = entry['sAMAccountName'][0].decode('utf-8')
        self.data[dn]['sam'] = sam
        self.map_user_dn[sam] = dn

    def handle_posix_account(self, dn, entry):
        # ldap account, only uidNumber & gidNumber
        self.data[dn]['objectClass'] = 'user'
        self.data[dn]['uidNumber'] = entry['uidNumber'][0].decode('utf-8')
        self.data[dn]['gidNumber'] = entry['gidNumber'][0].decode('utf-8')
        self.data[dn]['cn'] = entry['cn'][0].decode('utf-8')
        self.map_uidNumber_dn[self.data[dn]['uidNumber']] = dn

        uid = entry['uid'][0].decode('utf-8')

        self.data[dn]['sam'] = uid
        self.data[dn]['uid'] = uid
        self.map_user_dn[uid] = dn

    def handle_group(self, dn, entry):
        self.data[dn]['objectClass'] = 'group'
        # ad group member & memberOf are dn
        if 'gidNumber' in entry:
            gidNumber = entry['gidNumber'][0].decode('utf-8')
            self.self.data[dn]['gidNumber'] = gidNumber
            self.map_gidNumber_dn[gidNumber] = dn
            
        if 'sAMAccountName' in entry:
            sam = entry['sAMAccountName'][0].decode('utf-8')
            self.data[dn]['sam'] = sam
            self.map_group_dn[sam] = dn

        if 'member' in entry:
            for member in self.decode_str_list(entry['member']):
                
                self.data[dn]['member'].append(member)

                self.create_new(member)

                if dn in self.data[member]['memberOf']:
                    print("already a member")
                else:
                    self.data[member]['memberOf'].append(dn)

    def handle_posixgroup(self, dn, entry):
        # LDAP Group
        # UniqueMember is dn, member is uid
        # From what I see posixgroup does not require anything other than an ID
        # using cn as the group name for now, may need to revisit depending on 
        # different directory schemas
        self.data[dn]['objectClass'] = 'group'
        groupname = entry['cn'][0].decode('utf-8')
        self.data[dn]['sam'] = groupname
        self.data[dn]['cn'] = groupname
        gidNumber = entry['gidNumber'][0].decode('utf-8')
        self.data[dn]['gidNumber'] = gidNumber

        self.map_gidNumber_dn[gidNumber] = dn
        self.map_group_dn[groupname] = dn

        if 'UniqueMember' in entry:
            # UniqueMember is a distinguished name
            for member in self.decode_str_list(entry['UniqueMember']):
                if 'epederse' in member:
                    ecount = 0
                    ecount += 1

                self.data[dn]['member'].append(member)

                self.create_new(member)

                if dn in self.data[member]['memberOf']:
                    print("already a member")
                else:
                    self.data[member]['memberOf'].append(dn)

    def handle(self, dn, entry):

        dn = dn.lower()
        self.create_new(dn)  # create a blank entry with None values.

        oc = self.decode_str_list(entry['objectClass'])

        if 'user' in oc:
            self.handle_user(dn, entry)

        elif 'group' in oc:
            self.handle_group(dn, entry)

        elif 'posixaccount' in oc:
            self.handle_posix_account(dn, entry)

        elif 'posixgroup' in oc:
            self.handle_posixgroup(dn, entry)

    def check_unknown_members(self):
        for m in self.unknown_members:
            if not self.data[m]['objectClass'] == 'group':
                pass
                #print('unknown member: {}'.format(m))

    def check_has_nested_groups(self):
        print("Running Nested Group Check")
        count = 0
        processed = 0
        for dn in self.data:
            # even if i import from ldap I set internally objectClass to group
            # during the import.
            if self.data[dn]['objectClass'] == 'group':
                processed += 1
                if len(self.data[dn]['memberOf']) > 0:
                    print("Group {} is a nested group".format(dn))
                    count += 1
                for member_dn in self.data[dn]['member']:
                    if self.data[member_dn]['objectClass'] == 'group':
                        print("Group {} is a nested group".format(member_dn))
                        count += 1
        print(f"Processed {processed} groups, found {count} nested groups")
        return count

    def ldap_users_more_than_16_group(self):
        print("checking if user belongs to more than 16 groups")
        count = 0
        max = 0
        for u in self.data:
            if self.data[u]['objectClass'] == 'user':
                length = len(self.data[u]['memberOf'])
                if length > max:
                    max = length
                if len(self.data[u]['memberOf']) > 16:
                    count += 1
                    print(f"User {u} in more than 16 groups")
        print(f"Total: {count} maximum membership {max}")

    def check_uid_gid_mismatch(self, ldap):
        uidCount = 0
        gidCount = 0
        for item in self.data:
            if self.data[item]['objectClass'] == 'user':
                uidNumber = self.data[item]['uidNumber']
                gidNumber = self.data[item]['gidNumber']
                id = self.data[item]['sam']

                if uidNumber:
                    uidCount += 1

                    ldap_dn = ldap.map_user_dn[id]
                    if uidNumber != ldap.data[ldap_dn]['uidNumber']:
                        print("user uidNumber Mismatch")
                    if gidNumber != ldap.data[ldap_dn]['gidNumber']:
                        print("User gidNumber Mismatch")

            elif self.data[item]['objectClass'] == 'group':
                gidCount += 1
                gidNumber = self.data[item]['gidNumber']
                id = self.data[item]['sam']
                if gidNumber:

                    id = self.data[item]['sam']
                    if id in ldap.map_group_dn:
                        # checking
                        ldap_dn = ldap.map_user_dn[id]
                    else:
                        print(f"Ad account {id} with gidNumber")
                    if not gidNumber == ldap.data[ldap_dn]['gidNumber']:
                        print("gid Mismatch")

        print("Uids {}   GIDS {}".format(uidCount, gidCount))

def show_group(ad, ldap):
    for item in ad.data:
        if 'sam' in ad.data[item]:
            id = ad.data[item]['sam']
            if id in ldap.map_id_dn:
                ldap_dn = ldap.map_id_dn[id]

                id = ad.data[item]['sam']
                print("SAM: {}  ".format(id))
                print("ObjectClass: {}  ".format(ad.data[item]['objectClass']))
                print("groups")
                # pprint(ad.data[item]['memberOf'])

                ldap_dn = ldap.map_id_dn[id]
                print("LDAP")
                print("groups")
                pprint(ldap.data[ldap_dn]['memberOf'])


if __name__ == "__main__":
    parser = argparse.ArgumentParser("LDAP Usermapping Tool")
    parser.add_argument('--ad', type=str, help='Active Directory LDIF Dump file')
    parser.add_argument('--ldap', type=str, help='LDAP LDIF Dump file')
    args = parser.parse_args()

    ad = PureLDIF(args.ad)
    # ad.check_unknown_members()

    ldap = PureLDIF(args.ldap)
    # ldap.check_unknown_members()
    nested_count = ldap.check_has_nested_groups()
    print("ldap has nest count of {}".format(nested_count))


    check_uid_gid_mismatch(ad, ldap)

    nested_count = ad.check_has_nested_groups()
    print("AD has nest count of {}".format(nested_count))

    ad.ldap_users_more_than_16_group()
    ldap.ldap_users_more_than_16_group()

