// ════════════════════════════════════════════════
// SEED DATA
// ════════════════════════════════════════════════
var USERS = [
  // BD Team
  {id:"u1",name:"Prince Thomas",  email:"prince@futeglobal.com", role:"admin",empId:"FG-001",desig:"Business Development Manager",bdm:null,av:"PT",avc:"av-admin",plt:"Gmail"},
  {id:"u2",name:"Ash Sayyad",     email:"ash@futeglobal.com",    role:"bd",   empId:"FG-002",desig:"Business Development Manager",bdm:null,av:"AS",avc:"av-bd",  plt:"Gmail"},
  {id:"u3",name:"Pranay Narayan", email:"pranay@futeglobal.com", role:"bd",   empId:"FG-003",desig:"Business Development Manager",bdm:null,av:"PN",avc:"av-bd",  plt:"Gmail"},
  {id:"u4",name:"Sarah Smith",    email:"sarah@futeglobal.com",  role:"bd",   empId:"FG-004",desig:"Business Development Manager",bdm:null,av:"SS",avc:"av-bd",  plt:"Gmail"},
  {id:"u5",name:"Patrick Wilson", email:"patrick@futeglobal.com",role:"bd",   empId:"FG-005",desig:"Business Development Manager",bdm:null,av:"PW",avc:"av-bd",  plt:"Gmail"},
  {id:"u6",name:"Michael Smith",  email:"michael@futeglobal.com",role:"bd",   empId:"FG-006",desig:"Business Development Manager",bdm:null,av:"MS",avc:"av-bd",  plt:"Gmail"},
  {id:"u7",name:"Gregg Daniels",  email:"gregg@futeglobal.com",  role:"bd",   empId:"FG-007",desig:"Business Development Manager",bdm:null,av:"GD",avc:"av-bd",  plt:"Gmail"},
  // RA Team (unassigned — assign via Admin tab)
  {id:"u8", name:"Steven Parker",  email:"steven@futeglobal.com",  role:"ra",empId:"FG-008",desig:"Research Analyst",bdm:null,av:"SP",avc:"av-ra",plt:"Gmail"},
  {id:"u9", name:"Mick Thompson",  email:"mick@futeglobal.com",    role:"ra",empId:"FG-009",desig:"Research Analyst",bdm:null,av:"MT",avc:"av-ra",plt:"Gmail"},
  {id:"u10",name:"Dan Johnson",    email:"dan@futeglobal.com",     role:"ra",empId:"FG-010",desig:"Research Analyst",bdm:null,av:"DJ",avc:"av-ra",plt:"Gmail"},
  {id:"u11",name:"Amy Hernandez",  email:"amy@futeglobal.com",     role:"ra",empId:"FG-011",desig:"Research Analyst",bdm:null,av:"AH",avc:"av-ra",plt:"Gmail"},
  {id:"u12",name:"Jessica Davis",  email:"jessica@futeglobal.com", role:"ra",empId:"FG-012",desig:"Research Analyst",bdm:null,av:"JD",avc:"av-ra",plt:"Gmail"},
  {id:"u13",name:"Nancy Parker",   email:"nancy@futeglobal.com",   role:"ra",empId:"FG-013",desig:"Research Analyst",bdm:null,av:"NP",avc:"av-ra",plt:"Gmail"},
  {id:"u14",name:"Julia Jens",     email:"julia@futeglobal.com",   role:"ra",empId:"FG-014",desig:"Research Analyst",bdm:null,av:"JJ",avc:"av-ra",plt:"Gmail"},
  {id:"u15",name:"Diana Davis",    email:"diana@futeglobal.com",   role:"ra",empId:"FG-015",desig:"Research Analyst",bdm:null,av:"DD",avc:"av-ra",plt:"Gmail"},
  {id:"u16",name:"Anna Harper",    email:"anna@futeglobal.com",    role:"ra",empId:"FG-016",desig:"Research Analyst",bdm:null,av:"AH",avc:"av-ra",plt:"Gmail"},
  {id:"u17",name:"Justin Clark",   email:"justin@futeglobal.com",  role:"ra",empId:"FG-017",desig:"Research Analyst",bdm:null,av:"JC",avc:"av-ra",plt:"Gmail"},
  {id:"u18",name:"Lisa Anderson",  email:"lisa@futeglobal.com",    role:"ra",empId:"FG-018",desig:"Research Analyst",bdm:null,av:"LA",avc:"av-ra",plt:"Gmail"},
  {id:"u19",name:"Kristy Scott",   email:"kristy@futeglobal.com",  role:"ra",empId:"FG-019",desig:"Research Analyst",bdm:null,av:"KS",avc:"av-ra",plt:"Gmail"},
  {id:"u20",name:"Stephan Hunter", email:"stephan@futeglobal.com", role:"ra",empId:"FG-020",desig:"Research Analyst",bdm:null,av:"SH",avc:"av-ra",plt:"Gmail"},
  {id:"u21",name:"Melissa White",  email:"melissa@futeglobal.com", role:"ra",empId:"FG-021",desig:"Research Analyst",bdm:null,av:"MW",avc:"av-ra",plt:"Gmail"},
  {id:"u22",name:"David Miller",   email:"david@futeglobal.com",   role:"ra",empId:"FG-022",desig:"Research Analyst",bdm:null,av:"DM",avc:"av-ra",plt:"Gmail"},
  {id:"u23",name:"Daniel James",   email:"daniel@futeglobal.com",  role:"ra",empId:"FG-023",desig:"Research Analyst",bdm:null,av:"DJ",avc:"av-ra",plt:"Gmail"},
  {id:"u24",name:"Sharon Moss",    email:"sharon@futeglobal.com",  role:"ra",empId:"FG-024",desig:"Research Analyst",bdm:null,av:"SM",avc:"av-ra",plt:"Gmail"},
  {id:"u25",name:"Neal Patrick",   email:"neal@futeglobal.com",    role:"ra",empId:"FG-025",desig:"Research Analyst",bdm:null,av:"NP",avc:"av-ra",plt:"Gmail"}
];

var COMPANIES = [
  {id:"c1",name:"TechNova Solutions",web:"technova.io",ind:"Technology",loc:"Bangalore"},
  {id:"c2",name:"FinEdge Capital",web:"finedge.com",ind:"Finance",loc:"Mumbai"},
  {id:"c3",name:"HealthFirst Clinics",web:"healthfirst.in",ind:"Healthcare",loc:"Hyderabad"},
  {id:"c4",name:"BuildMax Infra",web:"buildmax.co.in",ind:"Manufacturing",loc:"Delhi"},
  {id:"c5",name:"RetailPro India",web:"retailpro.in",ind:"Retail",loc:"Chennai"},
  {id:"c6",name:"EduSpark",web:"eduspark.io",ind:"Education",loc:"Pune"},
  {id:"c7",name:"Nexus Consulting",web:"nexusconsult.com",ind:"Consulting",loc:"Bangalore"},
  {id:"c8",name:"MediaFlow",web:"mediaflow.in",ind:"Media",loc:"Mumbai"},
  {id:"c9",name:"LogiTrans",web:"logitrans.co.in",ind:"Logistics",loc:"Delhi"},
  {id:"c10",name:"LegalEdge",web:"legaledge.in",ind:"Legal",loc:"Hyderabad"},
  {id:"c11",name:"PropVault Realty",web:"propvault.in",ind:"Real Estate",loc:"Noida"},
  {id:"c12",name:"DataSense AI",web:"datasense.ai",ind:"Technology",loc:"Bangalore"}
];

var STAGES = ["Active","No Response","Negative","Positive","Connected","Future","Out of Office","Deactivated","Referred"];
var INDUSTRIES = ["Technology","Finance","Healthcare","Manufacturing","Retail","Education","Consulting","Media","Logistics","Legal","Real Estate"];
var SOURCES = ["LinkedIn","Indeed","Naukri","Company Website","Glassdoor","AngelList","Referral","Other"];
var POSITIONS = ["CTO","VP of Engineering","Head of Product","Procurement Director","Head of Digital","CFO","Director HR","VP Sales","Head of Operations","CMO","CHRO"];
var FIRSTNAMES = ["Arjun","Sunita","Vikram","Pooja","Rahul","Priya","Aditya","Sneha","Rohan","Meera","Karan","Divya","Amit","Neha"];
var LASTNAMES = ["Kapoor","Rao","Nair","Desai","Sharma","Singh","Mehta","Patel","Gupta","Kumar","Joshi","Verma"];
var RA_IDS = ["u8","u9","u10","u11","u12","u13","u14","u15","u16","u17","u18","u19","u20","u21","u22","u23","u24","u25"];
var RA_BD = {"u8":"u1","u9":"u1","u10":"u2","u11":"u2","u12":"u3","u13":"u3","u14":"u4","u15":"u4","u16":"u5","u17":"u5","u18":"u6","u19":"u6","u20":"u7","u21":"u7","u22":"u1","u23":"u2","u24":"u3","u25":"u4"};

function rp(arr){return arr[Math.floor(Math.random()*arr.length)]}
function rd(days){var d=new Date();d.setDate(d.getDate()-Math.floor(Math.random()*days));return d.toISOString().split("T")[0]}
function todayIST(){var n=new Date();return new Date(n.getTime()+5.5*3600000).toISOString().split("T")[0]}
function fmtDate(d){if(!d)return"—";var p=d.split("-");return p[2]+"/"+p[1]+"/"+p[0]}
function uname(id,users){var u=users.find(function(x){return x.id===id});return u?u.name:"—"}
function stageClass(s){return"st-"+s.replace(/ /g,"_")}

function genLeads(){
  var leads=[];var lid=1;
  COMPANIES.forEach(function(co){
    var n=Math.floor(Math.random()*4)+2;
    for(var j=0;j<n;j++){
      var aid=rp(RA_IDS);var bid=RA_BD[aid];
      var st=rp(STAGES);var dt=rd(30);
      var fn=rp(FIRSTNAMES);var ln=rp(LASTNAMES);
      leads.push({
        id:"l"+lid++,coid:co.id,pos:rp(POSITIONS),
        fn:fn,ln:ln,desig:rp(["CTO","VP Ops","Head of Digital","Director","CFO","CHRO"]),
        email:fn.toLowerCase()+"."+ln.toLowerCase()+"@"+co.web,
        phone:"+91 9"+Math.floor(Math.random()*8+1)+String(Math.random()).slice(2,10),
        li:"https://linkedin.com/in/"+fn.toLowerCase()+ln.toLowerCase(),
        src:rp(SOURCES),aid:aid,bid:bid,stage:st,date:dt,
        sent:st!=="Active"&&Math.random()>.3?dt:null,
        plt:rp(["Gmail","Outlook",null]),notes:"",del:null
      });
    }
  });
  return leads;
}

function genActs(leads){
  var acts=[];
  leads.forEach(function(l){
    acts.push({id:"a"+acts.length,lid:l.id,uid:l.aid,type:"created",txt:"Lead created",dt:l.date});
    if(l.sent)acts.push({id:"a"+acts.length,lid:l.id,uid:l.aid,type:"email",txt:"Email sent via "+(l.plt||"Gmail"),dt:l.sent});
    if(l.stage!=="Active")acts.push({id:"a"+acts.length,lid:l.id,uid:l.bid,type:"stage",txt:'Stage → "'+l.stage+'"',dt:l.date});
  });
  return acts;
}

