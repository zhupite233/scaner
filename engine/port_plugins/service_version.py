# --*-- coding: utf-8 --*--




def print_report(nmap_report):
    result = ''
    for host in nmap_report.hosts:
        if len(host.hostnames):
            tmp_host = host.hostnames.pop()
        else:
            tmp_host = host.address

        result += "Scan report for {0} ({1})\n".format(tmp_host, host.address)
        result += "Host is {0}.\n".format(host.status)
        result += " PORT    STATE   SERVICE\n"

        for serv in host.services:
            pserv = "{0:>5s}/{1:3s} {2:12s} {3}\n".format(
                str(serv.port),
                serv.protocol,
                serv.state,
                serv.service)
            if len(serv.banner):
                pserv += " ({0})".format(serv.banner)
            result += pserv
        result += nmap_report.summary
        return result


