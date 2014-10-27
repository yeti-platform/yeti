import threading
import datetime
import time
from multiprocessing import Queue, Process

import adns


class AsyncResolver(object):
    """
    Resolves DNS queries asynchronously. Based on http://www.catonmat.net/blog/asynchronous-dns-resolution/
    Spawns a thread that will periodically check for results, and invoke a callback on them.
    """
    def __init__(self, callback, max_reqs=100):
        self.adns = adns.init()
        self.collect_results_thread = threading.Thread(target=self.collect_results)
        self.resolver_thread = threading.Thread(target=self.resolver)
        self.active = False
        self.active_queries = {}
        self.total_processed = 0
        self.callback = callback
        self.queue = Queue()
        self.max_reqs = threading.Semaphore(max_reqs)

    def start(self):
        self.active = True
        self.collect_results_thread.start()
        self.resolver_thread.start()

    def submit(self, hostname):
        self.max_reqs.acquire()
        self.queue.put(hostname)

    def resolver(self):
        while self.active:
            host = self.queue.get()
            if host == "BAIL":
                break
            self.resolve_all(host)

    def wait(self):
        self.resolver_thread.join()
        time.sleep(60)
        self.active = False
        self.collect_results_thread.join()

    def collect_results(self):
        while self.active:
            num_r = 0
            for query in self.adns.completed():
                num_r += 1
                answer = query.check()
                
                orig_query = self.active_queries.get(query, [])
                while orig_query == []: orig_query = self.active_queries.get(query, [])
                
                host = orig_query[0]
                rtype = orig_query[1]
                del self.active_queries[query]

                if answer[0] == 0:
                    self.callback(host, rtype, answer)

                elif answer[0] == 101: # resolve CNAMEs
                    pass
                    # self.resolve(answer[1])
                    # self.callback(host, rtype, answer)

                self.max_reqs.release()

            if num_r > 0:
                self.total_processed += num_r

            time.sleep(0.5)

    def resolve_all(self, host):
        self.resolve(host, adns.rr.A)
        self.resolve(host, adns.rr.MX)
        self.resolve(host, adns.rr.NS)
        self.resolve(host, adns.rr.CNAME)

    def resolve(self, host, rr=adns.rr.A):
        query = self.adns.submit(host, rr)
        self.active_queries[query] = (host, rr)

    def bulk_resolve(self, host_list, rr=adns.rr.A):
        for host in host_list:
            query = self.adns.submit(host, rr)
            self.active_queries[query] = (host, rr)

def just_print(host, rtype, answer):
    print "%s -> %s (%s)" % (host, answer[3], rtype)


class Dummy(Process):

    def __init__(self):
        super(Dummy, self).__init__()

    def just_print(self, host, rtype, answer):
        print "%s -> %s (%s)" % (host, answer[3], rtype)

    def run(self):
        self.ar = AsyncResolver(self.just_print, max_reqs=500)
        self.ar.start()

        hosts = ['malcom.io', 'google.com', 'tomchop.me']

        for h in hosts:
            self.ar.resolve_all(h)
            time.sleep(1)


# sample usage
if __name__ == '__main__':
    hosts = [line.rstrip('\n') for line in open('hostnames.txt', 'r')]
    ar = AsyncResolver(callback=just_print, max_reqs=500)