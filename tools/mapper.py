
from pprint import pprint

from ldif_parse import PureLDIF
import argparse
import concurrent.futures

def create_ps(ldap, ad, args):
    # user & group are the short name like sam & uid
    ldap_group_dns = {} # keep track of relevant groups to the user list provided
    undo_cmds = []

    # user attributes we want to copy from ldap -> AD
    user_attributes = ['uidNumber', 'gidNumber', 'unixHomeDirectory', 'loginShell']

    # args.users is supplied by the command line
    if args.allusers:
        # get all ldap objects, with objectClass == User
        userlist = [ldap.data[k]['sam'] for k in ldap.data if ldap.data[k]['objectClass'] == 'user']
    else:
        userlist = args.users
    for user in userlist:
        if user in ldap.map_user_dn:
            ldap_dn = ldap.map_user_dn[user]
            ldap_gidNumber = ldap.data[ldap_dn]['gidNumber']

            # keep track of which attributes we need to update in AD for this user
            attribs_need_update = {}

            # see if LDAP has the primary group
            # Just checking for oddness in LDAP
            # if ldap_gidNumber in ldap.map_gidNumber_dn:
            #    ldap_group_dn = ldap.map_gidNumber_dn[ldap_gidNumber]
            #    ldap_group_dns[ldap_group_dn] = True
            # else:
            #    print(f"# LDAP is missing primary group for user {user}, gidNumber{ldap_gidNumber}")
                

            # Does the user already exist in AD ?
            in_ad = False
            if user in ad.map_user_dn:
                ad_dn = ad.map_user_dn[user]
                in_ad = True
            else:
                print(f"# Need to create user {user} not in AD")
                
                

            # go through all attributes and check if we need to update them.
            for a in user_attributes:
                if in_ad:
                    if a in ldap.data[ldap_dn] and a in ad.data[ad_dn]:
                        if ad.data[ad_dn][a] == ldap.data[ldap_dn][a]:
                            # We Match yeah!!  nothing to do for this attrib
                            continue
                attribs_need_update[a] = ldap.data[ldap_dn][a]

            if len(attribs_need_update) == 0:
                print(f"# User {user} matches, no update needed.")
            else:
                attrib_cmds = []
                for a in attribs_need_update:
                    attrib_cmds.append(f"{a}=\"{attribs_need_update[a]}\"")

                    original_value = None
                    if a in ad.data[ad_dn]:
                        original_value = ad.data[ad_dn][a]
                    if original_value:
                        undo_cmds.append(f"Set-ADUser -Identity {user} -replace @{{{a}=\"{original_value}\"}}")
                    else:
                        undo_cmds.append(f"Set-ADUser -Identity {user} -clear {a}")

                ps_cmd = "Set-ADUser -Identity {} -replace @{{{}}}"
                print(ps_cmd.format(user, "; ".join(attrib_cmds)))

            # add all the groups i'm a member of to the list to check
            for g in ldap.data[ldap_dn]['memberOf']:
                ldap_group_dns[g] = True
        else:
            print(f"# User {user} not found in ldap")

    for ldap_group_dn in ldap_group_dns:

        if ldap_group_dn in ldap.data:
            ldap_group_sam = ldap.data[ldap_group_dn]['sam']
            ldap_gidNumber = ldap.data[ldap_group_dn]['gidNumber']
            prefix = args.group_prefix

            ldap_group_sam_prefix = prefix + ldap_group_sam
            # Does it already exist in AD ?
            in_ad = False

            if ldap_gidNumber in ad.map_gidNumber_dn:
                # lookup by gidNumber first
                ad_dn = ad.map_gidNumber_dn[ldap_group_sam]
                if ldap_group_sam_prefix != ad.data[ad_dn]['sam']:
                    print("# Found existing group in AD by gidNumber but different sam, skipping")
                    print(f"# ldap: {ldap_group_sam_prefix} AD {ad.data[ad_dn]['sam']} gid: {ldap_gidNumber}")
                    continue  # Human need to resolve, 
                in_ad = True
            elif ldap_group_sam_prefix in ad.map_group_dn:
                # otherwise lets try and find the group
                ldap_group_sam = ldap_group_sam_prefix
                ad_dn = ad.map_group_dn[ldap_group_sam]
                in_ad = True
            else:
                ldap_group_sam = ldap_group_sam_prefix
                print(f"# Need to create group {ldap_group_sam} not in AD")
                print(f'New-ADGroup -Name "{ldap_group_sam}" -SamAccountName "{ldap_group_sam}" -GroupCategory Security -GroupScope Global -Path "{args.group_ou_dn}"')
                undo_cmds.append(f'Remove-ADGroup -Identity "{ldap_group_sam}"')



            if not in_ad or (in_ad and ad.data[ad_dn]['gidNumber'] != ldap_gidNumber):
                ps_cmd = "Set-ADGroup -Identity {} -replace @{{ gidNumber=\"{}\"}}"
                print(ps_cmd.format(ldap_group_sam, ldap_gidNumber))
                a = 'gidNumber'
                original_value = None
                if a in ad.data[ad_dn]:
                    original_value = ad.data[ad_dn][a]
                if original_value:
                    undo_cmds.append(f"Set-ADGroup -Identity {user} -replace @{{{a}=\"{original_value}\"}}")
                else:
                    undo_cmds.append(f"Set-ADGroup -Identity {user} -clear {a}")

            # check group members in ldap that don't existin in the AD group
            for ldap_member_dn in ldap.data[ldap_group_dn]['member']:
                if ldap_member_dn in ldap.data:  # does LDAP have this member sam ? 
                    member_sam = ldap.data[ldap_member_dn]['sam']
                    if not member_sam or member_sam not in userlist:
                        # only add members we care about 
                        continue

                    if in_ad:
                        # this means we have a target group in ad already, but the member is
                        # different
                        # this assumes no nested groups, we are assuming a member is a user
                        # need to translate ldap user dn -> ad user dn
                        if member_sam in ad.map_user_dn:
                            member_ad_dn = ad.map_user_dn[member_sam]
                            
                            # now we can check if the dn in already a member in the ad Group
                            if member_ad_dn in ad.data[ad_dn]['member']:
                                print(f"# Skipping {member_sam} correctly in AD group {ldap_group_sam}")
                                continue

                    #okay we need to add this member into the ad group:
                    print(f"Add-ADGroupMember -Identity {ldap_group_sam} -Members {member_sam}")
                    undo_cmds.append(f"Remove-ADGroupMember -Identity {ldap_group_sam} -Members {member_sam}")

                    continue

                print(f"# Unable to find ad member SAM for ldap group  {ldap_group_sam} member {ldap_member_dn}")
                

            # check for members that exist in AD but don't appear in ldap
            if in_ad:
                # if not ad can't have any members... so all good
                for ad_member_dn in ad.data[ad_dn]['member']:
                    # members are users, get the sam to find ldap user
                    # I should have used sam as the main key...
                    # need to get the sam... again
                    if ad_member_dn in ad.data:
                        ad_member_sam = ad.data[ad_member_dn]['sam']
                        if ad_member_sam in ldap.map_user_dn:
                            ad_member_ldap_dn = ldap.map_user_dn[ad_member_sam]
                            if ad_member_ldap_dn not in ldap[ldap_group_dn]['member']:
                                # okay htis means we need to remove an entry from AD as this member isn't 
                                # seen on the LDAP side gorup
                                print(f"Remove-ADGroupMember -Identity {ldap_group_sam} -Members {ad_member_sam}")
                                undo_cmds.append(f"Add-ADGroupMember -Identity {ldap_group_sam} -Members {ad_member_sam}")
                    else:
                        print("# could not find user in ad 2342")


            # check ad for groups with the prefix that don't exist in AD anymore
            # Todo: groups
    return undo_cmds

            
            
def print_ldapsearch():
    print("ldapsearch -H <ldap server> -b <search base> -D <bind user> -W -s sub -E pr=1000/noprompt "
          "'(&(|(objectclass=user)(objectclass=posixAccount)(objectclass=group)(objectclass=posixGroup))(!(objectclass=computer)))'"
          " uid uidNumber gid gidNumber memberOf gecos Name GivenName sAMAccountName cn dn memberUid Member UniqueMember groupOfUniqueNames members objectClass primaryGroupID distinguishedName unixHomeDirectory loginShell"
    ) 


if __name__ == "__main__":
    parser = argparse.ArgumentParser("LDAP Usermapping Tool")
    parser.add_argument('--ldapsearch', action='store_true',
      help='Print ldapsearch command you can use to pull ldap data')
    parser.add_argument('--ad', type=str, help='Active Directory LDIF Dump file')
    parser.add_argument('--ldap', type=str, help='LDAP LDIF Dump file')
    parser.add_argument('--group-prefix', type=str, default="ldapmap_", 
      help="prefix for the imported ldap groups into AD")
    parser.add_argument('--group-ou-dn', type=str, 
      help="Full DN for the OU to create groups into")
    parser.add_argument('-u', '--users', nargs='+', default=[])
    parser.add_argument('--allusers', action='store_true', help="Look at ALL users in LDAP, ignores --users")
    parser.add_argument('--undo', type=str, help="Write a list of undo command to file which will reverse the changes." )
    args = parser.parse_args()

    if args.ldapsearch:
        print_ldapsearch()
        exit()

    # parse both files at the same time in threads:
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_ad = executor.submit(PureLDIF, args.ad)
        future_ldap = executor.submit(PureLDIF, args.ldap)
        ad = future_ad.result()
        ldap = future_ldap.result()
    
    undo_cmds = create_ps(ldap, ad, args)

    if args.undo:
        with open(args.undo, "w") as outfile:
            outfile.write('\n'.join(undo_cmds)+'\n')


