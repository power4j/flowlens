using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Security.Cryptography;
using System.Collections.Generic;

public static class TlsStatePressure {
 const long Epoch=1800000000000000;
 static string Root,Suite; static BinaryWriter Cap; static StreamWriter Ledger; static int Frame,Next;
 static readonly Dictionary<string,int> Gens=new();
 static readonly Dictionary<string,long> Held=new();
 static readonly Dictionary<string,(long recv,long sent)> Domains=new();
 static readonly List<object> Cases=new();
 static byte[] Cat(params byte[][] xs)=>xs.SelectMany(x=>x).ToArray();
 static byte[] U16(int n)=>new[]{(byte)(n>>8),(byte)n};
 static byte[] U32(uint n)=>new[]{(byte)(n>>24),(byte)(n>>16),(byte)(n>>8),(byte)n};
 static string Hash(byte[] b)=>Convert.ToHexString(SHA256.HashData(b));
 static void Json(string path,object value)=>File.WriteAllText(path,JsonSerializer.Serialize(value,new JsonSerializerOptions{WriteIndented=true}));
 static ushort Checksum(byte[] b){uint s=0;for(int i=0;i<b.Length;i+=2)s+=(uint)((b[i]<<8)+(i+1<b.Length?b[i+1]:0));while(s>>16!=0)s=(s&65535)+(s>>16);return (ushort)~s;}
 static byte[] Hello(string host,int total=0){
  var name=Encoding.ASCII.GetBytes(host);var sni=Cat(U16(0),U16(name.Length+5),U16(name.Length+3),new byte[]{0},U16(name.Length),name);
  int baseSize=4+2+32+1+2+2+1+1+2+sni.Length;
  int records=total>16005?(total+15999)/16000:1;
  int padding=total==0?0:total-baseSize-records*5-4;
  if(padding<0||padding>65500)throw new Exception("padding length");
  var ext=padding==0?sni:Cat(sni,U16(21),U16(padding),new byte[padding]);
  var body=Cat(new byte[]{3,3},new byte[32],new byte[]{0},U16(2),new byte[]{0,0x2f,1,0},U16(ext.Length),ext);
  var hs=Cat(new byte[]{1,(byte)(body.Length>>16),(byte)(body.Length>>8),(byte)body.Length},body);
  using var wire=new MemoryStream();for(int i=0;i<hs.Length;i+=16000){int n=Math.Min(16000,hs.Length-i);wire.Write(new byte[]{22,3,3,(byte)(n>>8),(byte)n});wire.Write(hs,i,n);}
  var hello=wire.ToArray();ValidateHello(hello,host);if(total>0&&hello.Length!=total)throw new Exception("exact wire length");
  string path=Path.Combine(Root,"hellos",host+"-"+hello.Length+".bin");File.WriteAllBytes(path,hello);return hello;
 }
 // Independent structural oracle checks complete messages before any candidate replay.
 static void ValidateHello(byte[] wire,string host){
  using var hs=new MemoryStream();int p=0;while(p<wire.Length){if(wire[p]!=22||wire[p+1]!=3)throw new Exception("record");int n=(wire[p+3]<<8)+wire[p+4];if(n<1||n>16384||p+5+n>wire.Length)throw new Exception("record size");hs.Write(wire,p+5,n);p+=n+5;}
  var b=hs.ToArray();if(b[0]!=1||4+(b[1]<<16)+(b[2]<<8)+b[3]!=b.Length)throw new Exception("handshake length");
  p=38;p+=1+b[p];int suites=(b[p]<<8)+b[p+1];p+=2+suites;p+=1+b[p];int ext=(b[p]<<8)+b[p+1];p+=2;if(p+ext!=b.Length)throw new Exception("extensions");
  var types=new HashSet<int>();string sni=null;while(p<b.Length){int t=(b[p]<<8)+b[p+1],n=(b[p+2]<<8)+b[p+3];p+=4;if(!types.Add(t)||p+n>b.Length)throw new Exception("extension bounds");if(t==0){int len=(b[p+3]<<8)+b[p+4];if(n!=len+5||((b[p]<<8)+b[p+1])!=n-2||b[p+2]!=0)throw new Exception("sni bounds");sni=Encoding.ASCII.GetString(b,p+5,len);}if(t==21&&b.Skip(p).Take(n).Any(x=>x!=0))throw new Exception("padding");p+=n;}if(sni!=host)throw new Exception("oracle SNI");
 }
 static void Open(string suite){Suite=suite;Frame=Next=0;Gens.Clear();Held.Clear();Domains.Clear();Cap=new BinaryWriter(File.Create(Path.Combine(Root,suite+".pcap")));Cap.Write(0xa1b2c3d4u);Cap.Write((ushort)2);Cap.Write((ushort)4);Cap.Write(0u);Cap.Write(0u);Cap.Write(65535u);Cap.Write(1u);Ledger=new StreamWriter(Path.Combine(Root,suite+".truth.jsonl"));}
 static void Close(int started,int resolved,Dictionary<string,int> reasons){Cap.Dispose();Ledger.Dispose();Cases.Add(new{suite=Suite,frames=Frame,started,resolved,reasons,domains=Domains.ToDictionary(x=>x.Key,x=>new{recv=x.Value.recv,sent=x.Value.sent})});}
 static Dictionary<string,int> Reasons(params (string,int)[] xs)=>xs.ToDictionary(x=>x.Item1,x=>x.Item2);
 static void New(string id){Gens[id]=++Next;Held[id]=0;}
 static void Packet(string id,int port,uint seq,long us,byte flags=16,byte[] payload=null,string state="Observing",string reason=null,string domain=null,bool resolve=false,bool inbound=false,uint ack=901,int? active=null,Dictionary<string,int> reasons=null,long? raw=null){
  payload??=Array.Empty<byte>();var local=new byte[]{192,0,2,10};var peer=new byte[]{198,51,100,5};var src=inbound?peer:local;var dst=inbound?local:peer;
  var tcp=Cat(U16(inbound?443:port),U16(inbound?port:443),U32(seq),U32((flags&16)!=0?ack:0),new byte[]{0x50,flags,0xff,0xff,0,0,0,0},payload);
  ushort sum=Checksum(Cat(src,dst,new byte[]{0,6},U16(tcp.Length),tcp));tcp[16]=(byte)(sum>>8);tcp[17]=(byte)sum;
  var ip=Cat(new byte[]{0x45,0},U16(20+tcp.Length),new byte[]{0,0,0x40,0,64,6,0,0},src,dst);sum=Checksum(ip);ip[10]=(byte)(sum>>8);ip[11]=(byte)sum;
  var frame=Cat(new byte[12],new byte[]{8,0},ip,tcp);Frame++;long at=Epoch+us;Cap.Write((uint)(at/1000000));Cap.Write((uint)(at%1000000));Cap.Write((uint)frame.Length);Cap.Write((uint)frame.Length);Cap.Write(frame);
  long backfill=resolve?Held[id]:0; if(domain!=null){var d=Domains.GetValueOrDefault(domain);Domains[domain]=inbound?(d.recv+frame.Length,d.sent+backfill):(d.recv,d.sent+backfill+frame.Length);}
  if(state=="Observing"||state=="Pending")Held[id]+=frame.Length;
  Ledger.WriteLine(JsonSerializer.Serialize(new{frame=Frame,id,port,local_ip="192.0.2.10",peer_ip="198.51.100.5",peer_port=443,seq,ack,flags,payload_bytes=payload.Length,payload_sha256=Hash(payload),bytes=frame.Length,direction=inbound?"Inbound":"Outbound",observed_at=at,generation=Gens[id],state,reason,domain,backfill_sent=backfill,resolve,active,reasons,raw}));
 }
 static void Syn(string id,int port,uint isn,long us=0){New(id);Packet(id,port,isn,us,2);}
 static void Terminal(string id,int port,uint seq,long us,string reason,int? active=null,Dictionary<string,int> reasons=null)=>Packet(id,port,seq,us,state:"Rejected("+reason+")",reason:reason,active:active,reasons:reasons);
 public static void Generate(string root){
  Root=Path.GetFullPath(root);if(Directory.Exists(Root))throw new Exception("Fresh corpus required");Directory.CreateDirectory(Root);Directory.CreateDirectory(Path.Combine(Root,"hellos"));
  var large=Hello("pressure.example",20000);var prefix=large.Take(12288).ToArray();
  Open("active");for(int i=0;i<4100;i++){string id="a"+i;Syn(id,10000+i,100,i);}
  for(int i=0;i<4100;i++)if(i<4)Terminal("a"+i,10000+i,101,10000+i,"GlobalBudgetEvicted",4096,Reasons(("GlobalBudgetEvicted",4)));else Packet("a"+i,10000+i,101,10000+i,active:4096,raw:0);
  Close(4100,0,Reasons(("GlobalBudgetEvicted",4),("ObservationTimeout",4096)));
  Open("global-raw");for(int i=0;i<1200;i++){Syn("r"+i,10000+i,100,i*2);Packet("r"+i,10000+i,101,i*2+1,24,prefix,"Pending");}
  // x64 Segment is 24B; admission reserves existing capacity plus 3*new bytes+2048.
  int retained=(33554432-2048)/(12288*3+24);if(retained!=909)throw new Exception("frozen x64 reservation");
  for(int i=0;i<1200;i++)if(i<1200-retained)Terminal("r"+i,10000+i,101,200000+i,"GlobalBudgetEvicted",retained,Reasons(("GlobalBudgetEvicted",1200-retained)));else Packet("r"+i,10000+i,101,200000+i,state:"Pending",active:retained,raw:retained*(12288*3+24));
  Close(1200,0,Reasons(("GlobalBudgetEvicted",291),("HandshakeTimeout",909)));
  Open("perflow");var sparse=Hello("sparse.example",1000);Syn("sparse",10000,100);
  for(int i=0;i<64;i++)Packet("sparse",10000,(uint)(102+i*2),i+1,24,new[]{sparse[1+i*2]},"Pending",active:1);
  TerminalPayload("sparse",10000,230,100,new[]{sparse[129]},"PerFlowBudget");
  var good=Hello("boundary-good.example",43000);var bad=Hello("boundary-bad.example",45000);
  Syn("good",10001,100,200);Packet("good",10001,101,201,24,good,"Resolved",domain:"boundary-good.example",resolve:true,active:0,raw:0);
  Syn("bad",10002,100,300);TerminalPayload("bad",10002,101,301,bad,"PerFlowBudget");
  int maximum=(131072-24)/3;if(maximum!=43682)throw new Exception("frozen nearest contiguous reservation");
  var exactGood=Hello("exact-good.example",maximum);var exactBad=Hello("exact-bad.example",maximum+1);
  Syn("exact-good",10003,100,400);Packet("exact-good",10003,101,401,24,exactGood,"Resolved",domain:"exact-good.example",resolve:true,active:0,raw:0);
  Syn("exact-bad",10004,100,500);TerminalPayload("exact-bad",10004,101,501,exactBad,"PerFlowBudget");Close(5,2,Reasons(("PerFlowBudget",3)));
  Deadline("observing",false,false);Deadline("no-progress",true,false);Deadline("absolute",true,true);Deadline("late-first",true,true,true);
  Generations();History();Json(Path.Combine(Root,"suites.json"),Cases);
  Json(Path.Combine(Root,"contract.json"),new{oracle="Independent TLS builder/length walker and predeclared packet ledger; candidate output never generates expected values",scope="candidate-only offline adversarial stress; no comparator benefit/representative recall claim",raw_limit=33554432,perflow_limit=131072,nearest_contiguous_wire_success=43682,nearest_contiguous_wire_failure=43683,nearest_success_reservation=131070,nearest_failure_reservation=131073,nearest_formula="floor((131072 - 24)/3); 3*wire+one x64 Segment; exact 131072 not attainable by integral wire lengths in this path",metadata_limit=16777216,active_limit=4096,segment_x64_bytes=24,raw_retained=909,raw_evictions=291,observing_seconds=5,no_progress_seconds=2,absolute_first_payload_seconds=5,created_plus_10="unreachable as the earliest deadline when first payload is strictly before observing created+5",history_prior_isns=4,history_tti_seconds=300,window="Full Stats wall-clock rolling windows unverified",legal_records_max=16000,complete_hellos="hellos/*.bin; independent structural validation before replay"});
 }
 static void TerminalPayload(string id,int port,uint seq,long us,byte[] b,string reason)=>Packet(id,port,seq,us,24,b,"Rejected("+reason+")",reason:reason,active:0,raw:0);
 static void Deadline(string name,bool payload,bool progress,bool late=false){
  Open(name);var hello=Hello("deadline.example",20000);long first=late?4900000:100000;
  for(int i=0;i<100;i++)Syn("t"+i,10000+i,100);
  if(payload)for(int i=0;i<100;i++)Packet("t"+i,10000+i,101,first,24,hello.Take(20).ToArray(),"Pending");
  if(progress)for(int n=1;n<=4;n++)for(int i=0;i<100;i++)Packet("t"+i,10000+i,(uint)(101+20+(n-1)*100),first+n*1000000,24,hello.Skip(20+(n-1)*100).Take(100).ToArray(),"Pending");
  long deadline=payload?first+(progress?5000000:2000000):5000000;
  // ACK and identical payload retransmissions must not change expiry or progress.
  for(int i=0;i<100;i++)Packet("t"+i,10000+i,101,deadline-1,state:payload?"Pending":"Observing",active:100,reasons:Reasons());
  if(payload)for(int i=0;i<100;i++)Packet("t"+i,10000+i,101,deadline-1,24,hello.Take(20).ToArray(),"Pending",active:100);
  string reason=payload?"HandshakeTimeout":"ObservationTimeout";
  for(int i=0;i<100;i++)Terminal("t"+i,10000+i,101,deadline+1,reason,0,Reasons((reason,100)));
  Close(100,0,Reasons((reason,100)));
 }
 static void Generations(){
  Open("generations");var old=Hello("old.example");var newer=Hello("new.example");var fin=Hello("fin.example");
  for(int i=0;i<100;i++){
   int port=10000+i;long t=i*1000;string a="old"+i,b="new"+i;
   Syn(a,port,100,t);Packet(a,port,101,t+1,24,old.Take(20).ToArray(),"Pending");
   Syn(b,port,2000000,t+2);Packet(b,port,2000000,t+3,2);Packet(b,port,2000001,t+4,24,newer,"Resolved",domain:"new.example",resolve:true);
   Packet(b,port,100,t+5,2,state:"Resolved",reason:"GenerationAmbiguous");Packet(b,port,101,t+6,24,old,"Resolved","GenerationAmbiguous");Packet(b,port,101,t+7,state:"Resolved",reason:"GenerationAmbiguous");
   Packet(b,port,(uint)(2000001+newer.Length),t+8,state:"Resolved",domain:"new.example");
   Packet(b,port,(uint)(2000001+newer.Length),t+9,20,state:"Resolved",domain:"new.example");
   Packet(b,port,(uint)(2000001+newer.Length),t+10,state:"Resolved",reason:"GenerationAmbiguous");
  }
  for(int i=0;i<100;i++){int port=11000+i;long t=200000+i*1000;string id="rst"+i;Syn(id,port,100,t);Packet(id,port,101,t+1,24,old.Take(20).ToArray(),"Pending");Packet(id,port,121,t+2,20,state:"Rejected(ClosedBeforeHello)",reason:"ClosedBeforeHello");}
  for(int i=0;i<100;i++){int port=12000+i;long t=400000+i*1000;string id="fin"+i;Syn(id,port,100,t);Packet(id,port,101,t+1,24,fin.Take(20).ToArray(),"Pending");Packet(id,port,(uint)(101+fin.Length),t+2,17,state:"Pending");Packet(id,port,121,t+3,24,fin.Skip(20).ToArray(),"Resolved",domain:"fin.example",resolve:true);Packet(id,port,901,t+4,17,state:"Resolved",domain:"fin.example",inbound:true,ack:(uint)(102+fin.Length));}
  Close(400,200,Reasons(("GenerationReplaced",100),("ClosedBeforeHello",100)));
 }
 static void History(){
  Open("history");var h=Hello("history.example");
  for(int i=0;i<100;i++){
   int port=10000+i;long t=i*1000;for(int g=0;g<6;g++){string id=$"h{i}-{g}";uint isn=(uint)(100+g*2000000);Syn(id,port,isn,t+g*10);Packet(id,port,isn+1,t+g*10+1,24,h,"Resolved",domain:"history.example",resolve:true);}
   string current=$"h{i}-5";for(int g=1;g<=4;g++)Packet(current,port,(uint)(100+g*2000000),t+61+g,2,state:"Resolved",reason:"GenerationAmbiguous");
   Syn($"h{i}-outside-four",port,100,t+70);Packet($"h{i}-outside-four",port,101,t+71,24,h,"Resolved",domain:"history.example",resolve:true);
  }
  // After 300s idle expiry, the tuple has no generation history: same old ISN is new.
  for(int i=0;i<100;i++){string id=$"expired{i}";int port=10000+i;long t=301000000+i;Syn(id,port,100,t);Packet(id,port,101,t+1,24,h,"Resolved",domain:"history.example",resolve:true);}
  Close(800,800,Reasons());
 }
 static string Text(JsonElement e,string key)=>e.GetProperty(key).ValueKind==JsonValueKind.Null?null:e.GetProperty(key).GetString();
 static long Num(JsonElement e,string key)=>e.GetProperty(key).GetInt64();
 static void Require(bool yes,string message){if(!yes)throw new Exception(message);}
 static void Diag(JsonElement d,string context){
  long started=Num(d,"started"),resolved=Num(d,"resolved"),active=Num(d,"active"),terminal=d.GetProperty("reasons").EnumerateObject().Sum(x=>x.Value.GetInt64());
  Require(started==resolved+active+terminal,context+" state conservation");Require(active<=4096&&Num(d,"active_peak")<=4096,context+" active budget");Require(Num(d,"raw_reserved")<=33554432&&Num(d,"raw_peak")<=33554432,context+" raw budget");Require(Num(d,"metadata_reserved")<=16777216&&Num(d,"metadata_peak")<=16777216,context+" metadata budget");Require(Num(d,"delivery_failures")==0&&Num(d,"delivery_failed_bytes")==0,context+" delivery failures");
 }
 public static string Compare(string corpus,string suite,string output){
  var truth=File.ReadLines(Path.Combine(corpus,suite+".truth.jsonl")).Select(x=>JsonDocument.Parse(x)).ToArray();var actual=File.ReadLines(output).Select(x=>JsonDocument.Parse(x)).ToArray();Require(actual.Length==truth.Length+1,"frame row count");
  long sent=0,recv=0;var deliveries=new HashSet<long>();var expectedDomains=new Dictionary<string,(long recv,long sent)>();
  for(int i=0;i<truth.Length;i++){
   var e=truth[i].RootElement;var a=actual[i].RootElement;string c=suite+" frame "+(i+1);
   foreach(string k in new[]{"frame","bytes","port","peer_port","observed_at","generation"})Require(Num(e,k)==Num(a,k),c+" "+k);
   foreach(string k in new[]{"local_ip","peer_ip","direction","state","reason","domain"})Require(Text(e,k)==Text(a,k),c+" "+k);
   Require(Text(a,"role")=="ConfirmedLocalInitiator",c+" role");Diag(a.GetProperty("diagnostics"),c);
   foreach(string k in new[]{"active","raw"})if(e.GetProperty(k).ValueKind!=JsonValueKind.Null)Require(Num(e,k)==Num(a.GetProperty("diagnostics"),k=="raw"?"raw_reserved":k),c+" checkpoint "+k);
   if(e.GetProperty("reasons").ValueKind!=JsonValueKind.Null)Require(e.GetProperty("reasons").GetRawText()==a.GetProperty("diagnostics").GetProperty("reasons").GetRawText(),c+" checkpoint reasons");
   bool backfill=e.GetProperty("resolve").GetBoolean();var bf=a.GetProperty("backfill");Require((bf.ValueKind!=JsonValueKind.Null)==backfill,c+" unexpected backfill");
   if(backfill){Require(Num(bf,"sent")==Num(e,"backfill_sent")&&Num(bf,"recv")==0,c+" backfill bytes");Require(deliveries.Add(Num(bf,"delivery")),c+" repeated delivery");}
   long bytes=Num(e,"bytes");bool inbound=Text(e,"direction")=="Inbound";if(inbound)recv+=bytes;else sent+=bytes;
   string domain=Text(e,"domain");if(domain!=null){var d=expectedDomains.GetValueOrDefault(domain);expectedDomains[domain]=inbound?(d.recv+bytes,d.sent+Num(e,"backfill_sent")):(d.recv,d.sent+bytes+Num(e,"backfill_sent"));}
  }
  var summary=actual.Last().RootElement;var diag=summary.GetProperty("diagnostics");Diag(diag,suite+" EOF");Require(Num(diag,"active")==0&&Num(diag,"raw_reserved")==0&&Num(diag,"metadata_reserved")==0,"EOF release");
  using var cases=JsonDocument.Parse(File.ReadAllText(Path.Combine(corpus,"suites.json")));var expected=cases.RootElement.EnumerateArray().Single(x=>Text(x,"suite")==suite);
  foreach(string k in new[]{"started","resolved"})Require(Num(expected,k)==Num(diag,k),suite+" final "+k);
  var er=expected.GetProperty("reasons").EnumerateObject().ToDictionary(x=>x.Name,x=>x.Value.GetInt64());var ar=diag.GetProperty("reasons").EnumerateObject().ToDictionary(x=>x.Name,x=>x.Value.GetInt64());Require(er.Count==ar.Count&&er.All(x=>ar.GetValueOrDefault(x.Key)==x.Value),suite+" final reasons");
  Require(Num(summary,"errors")==0&&Num(summary,"frames")==truth.Length&&Num(summary,"accepted")==truth.Length,"capture count");Require(Num(summary,"bytes")==sent+recv&&Num(summary,"interface_sent")==sent&&Num(summary,"interface_recv")==recv&&Num(summary,"ip_sent")==sent&&Num(summary,"ip_recv")==recv&&Num(summary,"attribution_total")==sent+recv,"ordinary bytes");
  var ad=summary.GetProperty("domains").EnumerateArray().ToDictionary(x=>Text(x,"host"),x=>(Num(x,"recv"),Num(x,"sent")));Require(ad.Count==expectedDomains.Count&&expectedDomains.All(x=>ad.ContainsKey(x.Key)&&ad[x.Key]==x.Value),"Stats domain totals");
  string result=JsonSerializer.Serialize(new{suite,pass=true,frames=truth.Length,bytes=sent+recv,started=Num(diag,"started"),resolved=Num(diag,"resolved"),reasons=ar,raw_peak=Num(diag,"raw_peak"),metadata_peak=Num(diag,"metadata_peak"),active_peak=Num(diag,"active_peak"),fp=0,wrong_generation=0,wrong_bytes=0,duplicate_bytes=0});foreach(var x in truth)x.Dispose();foreach(var x in actual)x.Dispose();return result;
 }
}
