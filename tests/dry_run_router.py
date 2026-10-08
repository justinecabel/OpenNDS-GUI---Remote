import importlib.util, os, tempfile, shutil, pathlib, json, threading, re
from unittest.mock import patch
root=pathlib.Path(tempfile.mkdtemp(prefix='opennds-preview-'))
for source in pathlib.Path('/data').glob('*.json'):
 shutil.copy2(source,root/source.name)
shutil.copy2('/data/fas.key',root/'fas.key')
os.environ['FAS_KEY_FILE']=str(root/'fas.key')
for name, filename in {'SEEN_FILE':'seen.json','DELETED_FILE':'deleted.json','MODE_FILE':'mode.json','LIMITS_FILE':'limits.json','APPLIED_FILE':'applied.json','SESSION_REFRESH_FILE':'session-refresh.json','BLOCK_FILE':'blocked.json','PUNISH_FILE':'punishment.json','PUNISH_TC_FILE':'punishment-tc.json','WAN_USAGE_FILE':'wan-usage.json','CLIENT_WAN_HISTORY_FILE':'client-wan-history.json','WAN_TRAFFIC_FILE':'wan-traffic.json','TRAFFIC_FILE':'traffic.json','DOMAIN_RANK_FILE':'domain-rank.json','SQM_CONDITIONAL_FILE':'sqm-conditional.json'}.items(): os.environ[name]=str(root/filename)
os.environ['HOSTED_PORTAL_DIR']=str(root/'portal')
os.environ['PORTAL_TYPE_FILE']=str(root/'portal-type.json')
os.environ['SESSION_SECRET']='isolated-readonly-check'
with patch('threading.Thread.start'):
 spec=importlib.util.spec_from_file_location('preview','/work/app.py'); manager=importlib.util.module_from_spec(spec); spec.loader.exec_module(manager)
original=manager.ssh; writes=[]
def checked(command,data=None,timeout=15):
 if re.search(r'\b(?:set|commit|add|change|delete|replace|modprobe|deauth|auth|trust|untrust)\b',command) and not command.startswith('set -e; echo @@TC_') and not command.startswith('attempt=1;'):
  writes.append(command)
  return 0,b'',''
 return original(command,data,timeout)
manager.ssh=checked
manager._refresh_trusted_macs_if_due()
snapshot=manager._collect_clients_snapshot()
assert snapshot['ok'],snapshot.get('output')
manager._clients_cache_data=snapshot
state=manager._load_mode(); limits=manager._load_limits(); policy=manager._load_punishment_policy()
clients=list(snapshot['_live_clients'].values())
desired=manager._managed_tc_clients(clients,policy,limits,manager._load_blocked(),manager._trusted_macs())
ok,msg=manager._apply_punishment_qdisc(policy,desired)
print(json.dumps({'queue_adoption_ok':ok,'message':msg,'planned_changes':writes,
                  'bindings':manager._punishment_tc_state().get('bindings'),
                  'pending':manager._punishment_tc_state().get('pending')},indent=2))
# Execute only the combined counter/conntrack read, never collector policy commands.
manager.ssh=original
sample=manager._read_traffic_counters(include_flows=True)
assert sample and sample['flow_raw']
ip_to_mac,active=manager._wan_usage_inputs(clients,sample['at'])
flows=manager._read_wan_flows(ip_to_mac,sample['flow_raw'])
print(json.dumps({'combined_sample_ok':bool(flows),'timestamp_shared':flows[0]==sample['at'] if flows else False,
                  'conntrack_flows':len(flows[3]) if flows else 0}))
# An existing client's valid FAS continuation must perform only a verified JSON lookup.
import base64,hashlib
client=next((c for c in clients if c.get('state')=='Authenticated'),None)
if client:
 manager.ssh=checked
 hid=hashlib.sha256(client['token'].encode()).hexdigest()
 raw=(f"hid={hid}, clientmac={client['mac']}, clientip={client['ip']}, "
      f"gatewayaddress={client['gatewayaddress']}, originurl=http://example.com/")
 response=manager.app.test_client().get('/fas/continue',query_string={'tok':base64.b64encode(raw.encode()).decode()})
 print(json.dumps({'existing_session_fas_status':response.status_code,'router_change_count':len(writes)}))
 assert not writes, 'Read-only dry-run unexpectedly proposed router changes'
 assert response.status_code==302, 'Existing client FAS verification failed'
