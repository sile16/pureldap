import nis


class NisUserMapper():

    # NIS usernames are case sensative
    # sAMACountName is NOT... so we try a case sensative match first, then
    # try a lowercase match.

    def user_sam_to_uidNumber_gidNumber(self, sam):
        try:
            result = nis.match(sam, 'passwd.byname').split(":")
            return (result[2], result[3])
        except nis.error:
            # lookup failed, try a lower case version
            # since  NIS is case sensative.
            sam = sam.lower()
            try:
                result = nis.match(sam, 'passwd.byname').split(":")
                return (result[2], result[3])
            except nis.error:
                pass

        return None

    def group_sam_to_gidNumber(self, sam):
        try:
            result = nis.match(sam, 'group.byname').split(":")
            return result[2]
        except nis.error:
            # lookup failed, try a lower case version
            # since  NIS is case sensative.
            sam = sam.lower()
            try:
                result = nis.match(sam, 'group.byname').split(":")
                return result[2]
            except nis.error:
                pass

        return None

    def uidNumber_to_sam(self, uidNumber):
        try:
            result = nis.match(uidNumber, 'passwd.byuid').split(":")
            return result[0]
        except nis.error:
            pass
        return None

    def gidNumber_to_sam(self, gidNumber):
        try:
            result = nis.match(gidNumber, 'group.bygid').split(":")
            return result[0]
        except nis.error:
            pass
        return None

    def sam_to_group_member_ids(self, sam):
        members_group_gids = []
        try:
            all_groups = nis.cat('group.bygid')
            for gid in all_groups:
                items = all_groups[gid].split(":")
                if len(items) == 4:
                    groups = items[3].split(",")
                    if sam in groups:
                        members_group_gids.append(gid)
        except nis.error:
            pass
        return members_group_gids


class TestUserMapper():
    # Test Mapper for dev & test purposes.
    # All names must be lower case and map to
    # uidNumber &  gidNumber as a tuple
    user_uid_gid_mapping = {'mrobertson': ('1010', '2010'),
                            'uidtest': ('1011', '2011'),
                            'administrator': ('1012', '2012')}

    # group gidNumber too, so you will have to have users and groups  here.
    group_gid_mapping = {'adunixmrobprimary': '2010',
                         'adunixuidtestprimary': '2011',
                         'adunixmrob': '3010',
                         'adunixuidtest': '3011',
                         'adunixboth': '3012',
                         'unixfindme': '83848586'}

    def user_sam_to_uidNumber_gidNumber(self, sam):

        if sam in self.user_uid_gid_mapping:
            return self.user_uid_gid_mapping[sam]
        return None

    def group_sam_to_gidNumber(self, sam):
        # returns gidNumber or None
        if sam in self.group_gid_mapping:
            return self.group_gid_mapping[sam]
        return None

    def uidNumber_to_sam(self, uidNumber):
        for u in self.user_uid_gid_mapping:
            if self.user_uid_gid_mapping[u][0] == uidNumber:
                return u
        return None

    def gidNumber_to_sam(self, gidNumber):
        for u in self.user_uid_gid_mapping:
            if self.user_uid_gid_mapping[u][0] == gidNumber:
                return u
        return None
