from subprocess import check_output, CalledProcessError, STDOUT


def whois(data):
    cmd = ['/usr/bin/whois', data]
    response = check_output(cmd)
    return response

print whois('tomchop.me')
