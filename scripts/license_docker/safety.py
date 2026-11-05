#!/usr/bin/env python3
"""Exercise Docker ownership/configuration guards using disposable sentinels."""
import argparse,json,pathlib,subprocess,tempfile,uuid
from run import Suite
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--report',required=True)
parser.add_argument('--image',default='arc-license-tests:dde0bbeb')
args=parser.parse_args()
run='arc-license-guard-'+uuid.uuid4().hex[:8]
suite=Suite(argparse.Namespace(state=tempfile.mkdtemp(prefix='arc-license-guard-'),run_id=run,image=args.image))
names=[run+'-foreign',run+'-owned']; network=run+'-foreign-net'; results=[]
def docker(*args):return subprocess.check_output(['docker',*args],text=True).strip()
try:
 docker('create','--name',names[0],'--label','arc-license-tests=guard-sentinel',args.image)
 docker('create','--name',names[1],'--label','arc-license-tests='+run,'-e','ARC_LICENSE_KEY=LOCAL-FIXTURE-SAFETY','-e','ARC_TIERED_STORAGE_COLD_ENABLED=true',args.image)
 docker('network','create','--label','arc-license-tests=guard-sentinel',network)
 for command in [('rm',names[0]),('start',names[0]),('network','create',network)]:
  try:suite.docker(*command);raise AssertionError('mutation accepted')
  except RuntimeError as error:assert 'unowned' in str(error)
  results.append({'check':'reject_'+command[0]+'_foreign_resource','result':'PASS'})
 assert docker('inspect','-f','{{.State.Status}}',names[0])=='created'
 results.append({'check':'foreign_container_unchanged','result':'PASS'})
 assert suite.verify_container(names[1],{'ARC_LICENSE_KEY':'LOCAL-FIXTURE-SAFETY','ARC_TIERED_STORAGE_COLD_ENABLED':'true'},suite.args.image)
 results.append({'check':'matching_container_accepted','result':'PASS'})
 try:suite.verify_container(names[1],{'ARC_LICENSE_KEY':'LOCAL-FIXTURE-CHANGED','ARC_TIERED_STORAGE_COLD_ENABLED':'true'},suite.args.image);raise AssertionError('drift accepted')
 except RuntimeError as error:assert 'drift' in str(error)
 results.append({'check':'changed_key_rejected','result':'PASS'})
 try:suite.verify_container(names[1],{'ARC_LICENSE_KEY':'LOCAL-FIXTURE-SAFETY'},suite.args.image);raise AssertionError('removed option accepted')
 except RuntimeError as error:assert 'drift' in str(error)
 results.append({'check':'removed_optional_key_rejected','result':'PASS'})
 try:suite.docker('run','-d','--network',network,'--name',run+'-attach',args.image);raise AssertionError('foreign attach accepted')
 except RuntimeError as error:assert 'unowned' in str(error)
 results.append({'check':'foreign_network_attachment_rejected','result':'PASS'})
 p=pathlib.Path(args.report);p.parent.mkdir(parents=True,exist_ok=True,mode=0o700);p.write_text(json.dumps({'results':results},indent=2));p.chmod(0o600)
 print(json.dumps(results))
finally:
 for name in names:subprocess.run(['docker','rm',name],capture_output=True)
 subprocess.run(['docker','network','rm',network],capture_output=True)
