from ldif_parse import PureLDIF

def parse_hnas_user_map(file_name):
    data = {}

    with open(file_name, 'r') as in_file:
        in_file.readline()
        in_file.readline()
        for line in in_file:
            line = line.replace('*', '')
            temp1 = line.split(')')
            if len(temp1) < 3:
                continue
            temp2 = temp1[0].split('(')
            uid = temp2[0].strip()
            uidNumber = temp2[1].strip()

            # Get NT ID and GUID
            temp2 = temp1[1].split('(')
            NT = temp2[0].strip()
            guid = temp2[1].strip()

            # parse NT into domain and id
            if '\\' in NT:
                temp2 = NT.split('\\')
                domain = temp2[0].strip()
                sam = temp2[1].strip()
                if sam != "unknown" and uid != "unknown" and sam != uid:
                    print("sam:{} uid:{} mismatch".format(sam, uid))

                if uidNumber != "unknown":
                    data[sam] = uidNumber
    return data


def find_columns(line: str):
    columns = []
    index = 0
    while index < len(line):
        col_begin = line.find('-', index)
        if(col_begin == -1):
            break
        col_end = line.find(' ', col_begin)
        columns.append((col_begin, col_end))
        index = col_end
    return columns


def split_columns(line: str, col_def: list):
    columns = []
    for c in col_def:
        if len(line) < c[1]:
            print("Error, column too short")
            return columns
        sub = line[c[0]:c[1] + 3].strip()
        columns.append(sub)
    return columns


def parse_hnas_group_map(file_name):
    data = {}

    with open(file_name, 'r') as in_file:
        in_file.readline()
        line = in_file.readline()
        col_def = find_columns(line)

        for line in in_file:
            if line == '\n':
                # There is a new header line midway through
                in_file.readline()
                line = in_file.readline()
                col_def = find_columns(line)

            cols = split_columns(line, col_def)
            sam = gid = gidNumber = "unknown"

            if len(cols) == 3:
                # todo finsih this part, first column of group map
                if '(' in cols[0]:
                    start = cols[0].rfind('(')
                    gid = cols[0][0:start-1].strip().replace('*', '')
                    gidNumber = cols[0][start+1:-1].replace('*', '')
                if '(' in cols[1]:
                    start = cols[1].rfind('(')
                    guid = cols[1][start+1:-1].replace('*', '')
                    NT = cols[1][0:start - 1]
                    if '\\' in NT:
                        temp2 = NT.split('\\')
                        domain = temp2[0].strip()
                        sam = temp2[1].strip()

                    if sam != "unknown" and gid != "unknown" and sam != gid:
                        print("sam uid mismatch")

                    data[sam] = gidNumber
            else:
                print("Unexpeccted number of columns")

    return data


def compare_user_map(a, b):
    for i in a:
        if i in b:
            if a[i] != b[i]:
                print("User ID Mismatch")
            else:
                pass
                # print("match")
        else:
            pass
            # print("mapping in a but not in b")


def check_group_lookup_in_ldap(gmap, ldap):
    print("Running Group Lookup in LDAP check")
    count = 0
    # does the group map match LDAP? name -> ID
    for g in gmap:
        count += 1

        idNumber = gmap[g]
        if idNumber and idNumber != "unknown":
            if g in ldap.map_group_dn:
                ldap_dn = ldap.map_group_dn[g]
                gidNumber = ldap.data[ldap_dn]['gidNumber']
                if gidNumber and idNumber != gidNumber:
                    print("!! map file different than ldap !!")
                    print(
                        "Map File {g}:{idNumber} , LDAP: {ldap_cn}:{ldap_gid} ")
            else:
                if idNumber in ldap.map_gidNumber_dn:
                    ldap_dn = ldap.map_gidNumber_dn[idNumber]
                    ldap_cn = ldap.data[ldap_dn]['cn']
                    ldap_gid = ldap.data[ldap_dn]['gidNumber']
                    print(
                        f"Map File {g}:{idNumber} , LDAP: {ldap_cn}:{ldap_gid} ")
                else:
                    print(f"Group {g}:{idNumber} doens't exist in ldap")

    print(f"Processed {count} records")


def check_user_lookup_in_ldap(umap, ldap):
    print("Running User Lookup in LDAP check")
    count = 0
    for u in umap:
        count += 1
        idNumber = umap[u]
        if idNumber and idNumber != "unknown":
            if u in ldap.map_user_dn:
                ldap_dn = ldap.map_user_dn[u]
                ldap_uidNumber = ldap.data[ldap_dn]['uidNumber']

                if ldap_uidNumber and idNumber != ldap_uidNumber:
                    print("!! User mapping different than ldap !!")
                    print(
                        f"Map File {u}:{idNumber} , LDAP: {ldap_cn}:{ldap_gid} ")
            else:
                if idNumber in ldap.map_uidNumber_dn:
                    ldap_dn = ldap.map_uidNumber_dn[idNumber]
                    ldap_id = ldap.data[ldap_dn]['uid']
                    ldap_uid = ldap.data[ldap_dn]['uidNumber']

                    print(
                        f"Map File {u}:{idNumber} , LDAP: {ldap_id}:{ldap_uid} ")
                else:
                    print(
                        f"Mapped User {u} id: {idNumber} doens't exist in ldap")

    print(f"Processed {count} records")




if __name__ == "__main__":

    # check_group_lookup_in_ldap(gmap1, ldap)
    # check_group_lookup_in_ldap(gmap2, ldap)
    # check_user_lookup_in_ldap(umap1, ldap)
    # check_user_lookup_in_ldap(umap2, ldap)
    umap1 = hnas1_user_map = parse_hnas_user_map(
        "tools/hnas_g600_user_mappings.txt")
    umap2 = hnas2_user_map = parse_hnas_user_map(
        "tools/hnas_h4080_user_mappings.txt")
    gmap1 = hnas1_group_map = parse_hnas_group_map(
        "tools/hnas_g600_group_mappings.txt")
    gmap2 = hnas1_group_map = parse_hnas_group_map(
        "tools/hnas_h4080_group_mappings.txt")


    compare_user_map(umap1, umap2)
    compare_user_map(umap2, umap1)

    
