"""Offline decode only. No camera, repair, flag writes or native calls."""
from pathlib import Path
import hashlib,json,re,struct,argparse
NONCE='00112233445566778899aabbccddeeff'
DB='f2620309212756f6e59d008796a38931e18ac352bf2f1c74d9bafe5f65d8e23b'
PHASE={1:'STARTED',2:'ACCEPTED',3:'RESTORE_INTENT',4:'READY',5:'DONE',6:'FAILURE'}
REASON={0:'none',1:'invalid_or_uncertain_journal',2:'latest_phase_not_ACCEPTED',3:'journal_publish_failed',4:'clock_or_sleep_failed',5:'READY_wait_expired',6:'authenticated_runtime_failure'}

def gx(b):
 r={'bytes_observed':len(b),'sha256':hashlib.sha256(b).hexdigest(),'valid_content':False,'errors':[]}
 if len(b)!=256:r['errors']=['length'];return r
 abi,n,seq,phase,code=struct.unpack_from('<IIQII',b,8);pid=struct.unpack_from('<I',b,120)[0]
 rawboot=b[48:88];boot=rawboot[:36].decode('ascii',errors='replace')
 r.update(magic=b[:8].decode('ascii',errors='replace'),abi=abi,declared_bytes=n,seq=seq,phase=phase,phase_name=PHASE.get(phase,'UNKNOWN'),code=code,nonce=b[32:48].hex(),boot=boot,candidate=b[88:120].hex(),pid=pid,extra_hex=b[124:224].hex(),digest_valid=hashlib.sha256(b[:224]).digest()==b[224:])
 e=r['errors']
 if b[:8]!=b'A7GXST01' or abi!=1 or n!=256:e.append('framing')
 if not 0<seq<=(1<<64)-5 or phase not in PHASE:e.append('seq_or_phase')
 if b[32:48].hex()!=NONCE:e.append('nonce')
 if b[88:120].hex()!=DB:e.append('candidate')
 if not r['digest_valid']:e.append('digest')
 if rawboot[36:]!=bytes(4) or not re.fullmatch('[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',boot):e.append('boot')
 extra=b[124:224];used=8 if phase==4 else 12 if phase==6 else 0
 if any(extra[used:]):e.append('reserved_extra')
 if phase in (4,6):r['im_start']=struct.unpack_from('<Q',extra)[0]
 if phase==6:r['owner_error']=struct.unpack_from('<I',extra,8)[0]
 r['valid_content']=not e
 r['metadata_checked']=False
 r['boundary']='Content only; file mode/root uidgid/nlink, current process/start, native map and namespace need independent Root evidence.'
 return r

def observer(b):
 if len(b)!=256:raise ValueError('observer length')
 if struct.unpack_from('<4I',b)!=(0x314f4241,1,0x3110e115,256):raise ValueError('observer framing/current v21 build')
 keys='launcher_pid shell_pid observer_parent worker_pid worker_ppid_before worker_ppid_after uid ancestry_qualified'.split();r=dict(zip(keys,struct.unpack_from('<8I',b,32)))
 r.update(dict(zip('launcher_start shell_start mono_begin_ns mono_end_ns'.split(),struct.unpack_from('<4Q',b,64))))
 r.update(dict(zip('boot_id_bytes im_pid im_seen status flags guard_code guard_reason journal_error'.split(),struct.unpack_from('<8I',b,96))))
 r['im_start']=struct.unpack_from('<Q',b,128)[0];r['boot']=b[136:172].decode('ascii',errors='replace');r['nonce']=b[16:32].hex()
 r.update(dict(zip('restored ready readonly attempted_rename'.split(),struct.unpack_from('<4I',b,240))))
 r['reason_name']=REASON.get(r['guard_reason'],'UNKNOWN');r['elapsed_ms']=(r['mono_end_ns']-r['mono_begin_ns'])//1000000
 r['boundary']='record.bin is O_EXCL and intentionally preserved; correlate its boot, never assume it is current.'
 return r

def restore_intent(b):
 if len(b)!=248 or b[:8]!=b'A7RV1401' or struct.unpack_from('<II',b,8)!=(1,248):raise ValueError('restore intent framing')
 if hashlib.sha256(b[:216]).digest()!=b[216:]:raise ValueError('restore intent digest')
 return {'boot':b[16:56].split(bytes(1))[0].decode(), 'pid':struct.unpack_from('<I',b,56)[0], 'start':struct.unpack_from('<Q',b,64)[0], 'stock_inode':struct.unpack_from('<Q',b,72)[0], 'candidate_inode':struct.unpack_from('<Q',b,80)[0], 'stock_sha256':b[88:120].hex(),'candidate_sha256':b[120:152].hex(),'old_state_a_sha256':b[152:184].hex(),'old_state_b_sha256':b[184:216].hex(),'digest_valid':True,'boundary':'Historical manual RV transaction evidence, not boot-guard output or current permission.'}

def restore_result(b):
 if len(b)!=40:raise ValueError('restore result length')
 return dict(zip('code verified stock_linked journal_archived journal_published candidate_published publication_fsynced readonly awaiting_new_boot error_number'.split(),struct.unpack('<10I',b)))

def summarize(a,b,current_boot=None):
 rows=[x for x in [a,b]if x is not None];valid=[x for x in rows if x.get('valid_content')]
 if len(valid)!=len(rows):return {'next_source_branch':'restore','reason':1,'observed_only':True}
 if len(valid)==2 and abs(valid[0]['seq']-valid[1]['seq'])!=1:return {'next_source_branch':'restore','reason':1,'observed_only':True}
 if not valid:return {'next_source_branch':'publish_STARTED_then_wait_current_READY','observed_only':True}
 best=max(valid,key=lambda r:r['seq'])
 if best['phase']!=2:return {'next_source_branch':'restore','reason':2,'highest_seq':best['seq'],'observed_only':True}
 return {'next_source_branch':'CONFIRMED_same_boot'if current_boot==best['boot']else'publish_STARTED_then_wait_current_READY','highest_seq':best['seq'],'observed_only':True}

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('file',type=Path);p.add_argument('--kind',choices=['gx','observer'],default='gx');a=p.parse_args();print(json.dumps((gx if a.kind=='gx'else observer)(a.file.read_bytes()),indent=2))
if __name__=='__main__':main()
