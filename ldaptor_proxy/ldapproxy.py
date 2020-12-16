from ldaptor.protocols import pureldap
from ldaptor.protocols.ldap.proxybase import ProxyBase
from twisted.internet import defer
from twisted.python import log
from usermapper import NisUserMapper

# we need to cache the DN names to SAM
# becasue the group member query is based on the
# DN, so need to check each DN to see if it's mapped to a sam
dn_to_sam_lookup = {}


def dn_cache_new(dn, sam):
    global dn_to_sam_lookup
    if isinstance(dn, list):
        if len(dn) > 0:
            dn = dn[0]
            dn_cache_new(dn, sam)
    else:
        dn_to_sam_lookup[dn] = sam


def get_sam_from_dn(dn):
    global dn_to_sam_lookup
    if dn in dn_to_sam_lookup:
        return dn_to_sam_lookup[dn]
    return None


def attributes_to_dict(attribs):
    # attribs is a list of tuples, with a str and
    # list of values (str, [valuue1, value1])
    # this puts it into a dictionary of keys and appends the lists.
    data = {}
    for a in attribs:
        # if we've already added this key in, safely
        # add another value to the list
        if a[0] in data:
            if isinstance(data[a[0]], (list,)):
                # log for now just interested if this ever happens
                log.msg("appendig data to attrib: Existing key/data {}/{} new value {}".
                        format(a[0], data[a[0]], a[1]))
                data[a[0]].append(a[1])
            else:
                # hmmm... wierd
                log.msg("WARNING: trying to parse attributes. Existing key/data {}/{} new value {}".
                        format(a[0], data[a[0]], a[1]))
        else:
            data[a[0]] = a[1]
    return data


# bitwise checks for SAMAccount Type
SAM_APP_BASIC_GROUP = 0x40000000
SAM_USER_OBJECT = 0x30000000
SAM_ALIAS_OBJECT = 0x20000000
SAM_GROUP_OBJECT = 0x10000000
SAM_DOMAIN_OBJECT = 0x00000000
SAM_ACCOUNT_TYPE_MASK = 0x70000000


class LDAPMappingProxy(ProxyBase):
    """
    A simple example of using `ProxyBase` to log requests and responses.
    """
    mapper = NisUserMapper()

    def handleProxiedResponse(self, response, request, controls):
        """
        Look at the response from the proxied server and map sam->uid,gid
        """

        if isinstance(request, pureldap.LDAPSearchRequest) and  \
           isinstance(response, pureldap.LDAPSearchResultDone):
            # log.msg("Multi Part-request completed")
            pass

        elif isinstance(request, pureldap.LDAPSearchRequest) and \
                isinstance(response, pureldap.LDAPSearchResultEntry):

            res_attributes = attributes_to_dict(response.attributes)
            if 'sAMAccountName' in res_attributes and \
                    'sAMAccountType' in res_attributes:
                sam = res_attributes['sAMAccountName'][0]
                samtype = int(
                  res_attributes['sAMAccountType'][0]) & SAM_ACCOUNT_TYPE_MASK

                interesting_items = ['memberOf', 'isMemberOf', 'member',
                                     'members', 'memberUid',
                                     'groupOfNames', 'groupOfUniqueNames']

                if any(item in interesting_items for item in request.attributes):
                    log.msg("Intersting Item: {}".format(sam))
                    log.msg("  Results: {}".format(res_attributes))

                if samtype == SAM_USER_OBJECT:
                    # user and primary group mapping

                    if 'uidNumber' in res_attributes:
                        log.msg("uidNumber already in upstream LDAP, {}->{} ".format(
                            sam, res_attributes['uidNumber']
                        ))
                    elif self.mapper.user_sam_to_uidNumber_gidNumber(sam):
                        uidNumber = self.mapper.user_sam_to_uidNumber_gidNumber(sam)[
                            0]
                        log.msg(
                            "Found user uid mapping {} -> {}".format(sam, uidNumber))
                        response.attributes.append(('uidNumber', [uidNumber]))

                    if 'gidNumber' in res_attributes:
                        log.msg("gidNumber already in upstream LDAP, {}->{} ".format(
                            sam, res_attributes['gidNumber']
                        ))
                    elif self.mapper.user_sam_to_uidNumber_gidNumber(sam):
                        gidNumber = self.mapper.user_sam_to_uidNumber_gidNumber(sam)[
                            1]
                        log.msg(
                            "Found user gid mapping {} -> {}".format(sam, gidNumber))
                        response.attributes.append(('gidNumber', [gidNumber]))

                    if 'distinguishedName' in request.attributes:
                        # cache the dn->sam
                        if 'distinguishedName' in res_attributes:
                            dn = res_attributes['distinguishedName']
                            dn_cache_new(dn, sam)

                elif samtype == SAM_GROUP_OBJECT or samtype == SAM_ALIAS_OBJECT:
                    # Group  mapping

                    if 'gidNumber' in res_attributes:
                        log.msg("gidNumber already in upstream LDAP, {}->{} ".format(
                            sam, res_attributes['gidNumber']
                        ))
                    elif self.mapper.group_sam_to_gidNumber(sam):
                        gidNumber = self.mapper.group_sam_to_gidNumber(sam)
                        log.msg(
                            "Found group gid mapping {} -> {}".format(sam, gidNumber))
                        response.attributes.append(('gidNumber', [gidNumber]))

                    if 'uidNumber' in request.attributes:
                        log.msg(
                            "Warning: uidNumber as part of group object,  is this a group:{}".format(sam))
                        # log.msg("Request => " + repr(request))
                        # log.msg("Response => " + repr(response))

                else:
                    log.msg(
                        "Search request of unknown SAM Type: {}".format(samtype))
                    # log.msg("Request => " + repr(request))
                    # log.msg("request attribs: {}".format(request.attributes))
                    # log.msg("Response => " + repr(response))

            else:
                # No saMAccount in response
                if request.baseObject == "":
                    # log.msg("base object request")
                    pass
                elif 'CN=Schema,CN=Configuration' in request.baseObject:
                    pass
                    # log.msg("Schema Search")
                elif '1.1' in request.attributes:
                    if len(res_attributes):
                        log.msg("Search request for uid using 1.1")
                        log.msg("Request => " + repr(request))
                        log.msg("Response => " + repr(response))
                elif 'objectSid' in request.attributes and \
                     len(request.attributes) == 1:
                    # just a sid lookup
                    pass
                else:
                    log.msg("Search request of other type")
                    log.msg("Request => " + repr(request))
                    # log.msg("request attribs: {}".format(request.attributes))
                    log.msg("Response => " + repr(response))

        elif isinstance(request, pureldap.LDAPBindRequest) and \
                isinstance(response, pureldap.LDAPBindResponse):
            if not (response.resultCode == 0 or response.resultCode == 14):
                #  0 is success , and 14 is inProgress
                #  So neither of those there is some problem
                log.msg('Failed Bind Request: {}'.format(repr(request)))
                log.msg('Failed Bind Response: {}'.format(repr(response)))

        elif isinstance(response,  pureldap.LDAPSearchResultReference):
            pass

        else:
            log.msg("not search, something else: ".format(
                type(request).__name__))
            log.msg("Request => " + repr(request))
            log.msg("Response => " + repr(response))

        return defer.succeed(response)

    def replace_filter_uid_gid(self, ldapfilter):
        """
        Look through the filter and replace all searched for uid or gid
        with it's correspdoning SAM
        """
        if isinstance(ldapfilter, pureldap.LDAPFilterSet):
            for f in ldapfilter.data:
                # recursively call this function to process all nested filters
                self.replace_filter_uid_gid(f)

        elif isinstance(ldapfilter, pureldap.LDAPFilter_equalityMatch):
            attribute_name = ldapfilter.attributeDesc.value
            sam = idnum = None
            if attribute_name == 'uidNumber':
                idnum = ldapfilter.assertionValue.value
                sam = self.mapper.uidNumber_to_sam(idnum)

            elif attribute_name == 'gidNumber':
                idnum = ldapfilter.assertionValue.value
                sam = self.mapper.gidNumber_to_sam(idnum)

            if sam:
                log.msg("updating request filter {}:{} -> {}".format(
                                            attribute_name, idnum, sam))
                ldapfilter.attributeDesc.value = 'sAMAccountName'
                ldapfilter.assertionValue.value = sam

    def find_in_filter(self, desc, ldapfilter):
        """
        Recursively search all filters and
        nested filter for attribute description
        And return it's value.
        """
        if isinstance(ldapfilter, pureldap.LDAPFilterSet):
            for f in ldapfilter.data:
                # recursively call this function to process all nested filters
                value = self.find_in_filter(desc, f)
                if value:
                    return value

        elif isinstance(ldapfilter, pureldap.LDAPFilter_equalityMatch):
            if ldapfilter.attributeDesc.value == desc:
                return ldapfilter.assertionValue.value

        return None

    def handleBeforeForwardRequest(self, request, controls, reply):
        # Need to add addtitional search attributes to make
        # mapping easier via either sam or uid

        if isinstance(request, pureldap.LDAPSearchRequest):
            # add sAMAccountName to search request Atrributes
            # so we will have it in the results to
            # in order to do the usermapping
            lookup_match = ['uidNumber', 'gidNumber', 'memberOf',
                            'members', 'memberUid', 'member', 'groupOfNames',
                            'groupOfUniqueNames', 'distinguishedName']

            if any(item in lookup_match for item in request.attributes):

                if 'sAMAccountName' not in request.attributes:
                    request.attributes.append('sAMAccountName')

                if 'sAMAccountType' not in request.attributes:
                    # add type so we will know if it's a user or group object.
                    request.attributes.append('sAMAccountType')

            # change all gidNumber & uidNumber references in
            # filter with SAM from our mapper
            self.replace_filter_uid_gid(request.filter)

            if self.find_in_filter('objectClass', request.filter) == "Group":
                # This is a query for membership
                # we are going to start sending replies with matched groups
                # from NIS before we query LDAP and send any matches from ldap
                memberDN = self.find_in_filter('member', request.filter)
                sam = get_sam_from_dn(memberDN)

                if memberDN and sam:
                    # get all groups
                    group_ids = self.mapper.sam_to_group_member_ids(sam)

                    for gid in group_ids:
                        # send a result for each group
                        # member from NIS UserMapper
                        reply(pureldap.LDAPSearchResultEntry(
                            objectName='',
                            attributes=[('gidNumber', [gid])]))

        return defer.succeed((request, controls))
