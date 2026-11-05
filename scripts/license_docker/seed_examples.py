#!/usr/bin/env python3
"""Configure dedicated scheduled-work examples through running Arc APIs only."""
import argparse
import datetime as dt
import json
from pathlib import Path
import time
import urllib.error
import urllib.request

from run import Suite, UTC


class Examples(Suite):
    def __init__(self,args):
        super().__init__(args)
        self.installations=json.loads((self.state/'report.json').read_text())['installations']

    def write_report(self):
        if not hasattr(self,'installations'):
            return
        self.private(self.state/'feature-examples-report.json',json.dumps(self.redact(dict(
            **self.provenance(),results=self.results,installations=self.installations)),indent=2))

    def database_api(self,node,path,payload=None,database='license_soak_retention'):
        info=self.nodes[node]
        headers={'Authorization':'Bearer '+info['token'],'X-Arc-Database':database}
        if isinstance(payload,str):data=payload.encode();headers['Content-Type']='text/plain'
        else:data=None if payload is None else json.dumps(payload).encode();headers['Content-Type']='application/json'
        req=urllib.request.Request(info['url']+path,data=data,headers=headers)
        try:response=urllib.request.urlopen(req,timeout=90)
        except urllib.error.HTTPError as error:response=error
        with response:
            body=response.read().decode()
            try:body=json.loads(body)
            except ValueError:pass
            return response.status,body

    def ensure(self,node,path,payload):
        code,rows=self.api(node,path)
        if code==200 and rows is None:rows=[]
        if code!=200 or not isinstance(rows,list):raise RuntimeError('cannot list '+path+': '+str((code,rows)))
        existing=next((r for r in rows if r.get('name')==payload['name']),None)
        if existing:
            drift=[key for key,value in payload.items() if existing.get(key)!=value]
            if drift:raise RuntimeError('refusing to execute an existing example with different configuration: '+','.join(drift))
            return existing
        code,body=self.api(node,path,payload)
        self.record('configured:'+payload['name'],code==201,(code,body))
        if code!=201:raise RuntimeError('cannot create '+payload['name'])
        return body

    def run(self):
        configured=[]
        for installation in self.installations:
            self.current=installation['id']
            names=[n for n,i in self.nodes.items() if i['install']==self.current and not(self.current=='license1' and i['role']=='r1')]
            ready=[n for n in names if self.api(n,'/ready/write')[0]==200]
            if len(ready)!=1:raise RuntimeError('expected exactly one live primary for '+self.current)
            node=ready[0]
            cq=self.ensure(node,'/api/v1/continuous_queries/',dict(
                name='license-soak-minute-aggregation',database='license_soak',source_measurement='license_soak_events',
                destination_measurement='license_soak_minute',interval='1m',is_active=True,
                query='SELECT max(time) AS time, count(*) AS event_count FROM license_soak.license_soak_events WHERE time >= {start_time} AND time < {end_time} HAVING count(*) > 0'))
            now=dt.datetime.now(UTC)
            execute=self.api(node,f'/api/v1/continuous_queries/{cq["id"]}/execute',
                {'start_time':(now-dt.timedelta(minutes=5)).isoformat(),'end_time':(now-dt.timedelta(seconds=1)).isoformat()},timeout=120)
            self.record('aggregation_example_executes',execute[0]==200 and execute[1].get('status')=='completed' and execute[1].get('records_written',0)>0,execute)
            policy=self.ensure(node,'/api/v1/retention/',dict(name='license-soak-expiring-data',database='license_soak_retention',
                measurement='ephemeral',retention_days=1,buffer_days=0,is_active=True))
            previous=self.database_api(node,'/api/v1/query',{'sql':"SELECT count(*) AS n FROM ephemeral WHERE age = 'current'"})
            current_before=self.count(previous[1]) if previous[0]==200 else 0
            stamp=time.time_ns()
            lines=''.join(f'ephemeral,age={age},record_id={i} value={i}i {stamp-offset+i}\n'
                for age,offset in [('old',3*24*3600*10**9),('current',0)] for i in range(10))
            ingest=self.database_api(node,'/api/v1/write/line-protocol',lines)
            self.record('retention_fixture_ingested',ingest[0]==204,ingest)
            time.sleep(2)
            preview=self.api(node,f'/api/v1/retention/{policy["id"]}/execute',{'dry_run':True},timeout=120)
            self.record('retention_preview',preview[0]==200,preview)
            actual=self.api(node,f'/api/v1/retention/{policy["id"]}/execute',{'dry_run':False,'confirm':True},timeout=120)
            self.record('retention_example_executes',actual[0]==200,actual)
            count=self.database_api(node,'/api/v1/query',{'sql':'SELECT count(*) AS n FROM ephemeral'})
            self.record('retention_keeps_current_rows',count[0]==200 and self.count(count[1])==current_before+10,count)
            configured.append(dict(id=self.current,cq_id=cq['id'],retention_id=policy['id']))
        self.private(self.state/'feature-examples.json',json.dumps(configured,indent=2))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state',required=True)
    parser.add_argument('--run-id',default='arc-license-live')
    parser.add_argument('--image',default='arc-license-tests:dde0bbeb')
    suite=Examples(parser.parse_args());suite.run()
    return int(any(r['result']=='FAIL' for r in suite.results))


if __name__=='__main__':raise SystemExit(main())
