const {JSDOM}=require("jsdom"),fs=require("fs");
const src=fs.readFileSync(__dirname+"/../app/static/probe.js","utf8");
function run(name,{atPre,webdriver,fetchJson},cb){
  const dom=new JSDOM("<!doctype html><body><p>hi</p></body>",{runScripts:"outside-only",url:"https://site.test/about",pretendToBeVisual:true});
  const w=dom.window,beacons=[];
  if(webdriver)Object.defineProperty(w.navigator,"webdriver",{value:true});
  w.navigator.sendBeacon=(u,b)=>{beacons.push([u,JSON.parse(b)]);return true};
  w.fetch=()=>Promise.resolve({json:()=>Promise.resolve(fetchJson)});
  if(atPre)w.__AT=atPre;
  w.eval(src);
  w.cdc_adoQpoasnfa76pfcZLmcfl_Array=1; // simulated chromedriver global
  setTimeout(()=>{
    w.dispatchEvent(new w.MouseEvent("mousemove"));w.dispatchEvent(new w.MouseEvent("mousemove"));
    w.dispatchEvent(new w.MouseEvent("click"));
    const x=new w.Event("keydown"); w.dispatchEvent(x);
    // agent UI injected after load
    const n=w.document.createElement("div");n.id="genspark-float-bar";w.document.body.appendChild(n);
    setTimeout(()=>cb(name,w,beacons),4300);
  },300);
}
let fails=0;const ok=(n,c)=>{console.log((c?"  PASS ":"  FAIL ")+n);if(!c)fails++};
run("trap-page mode",{atPre:{t:"p-abc-0000000000",rx:"(genspark|copilot)",sel:["#genspark-float-bar"]},webdriver:true},(n,w,b)=>{
  console.log(n);
  ok("beacon sent once after 4s",b.length===1&&b[0][0]==="/_at/p");
  const d=b[0][1].d;
  ok("token forwarded",b[0][1].t==="p-abc-0000000000");
  ok("webdriver detected",d.webdriver===true);
  ok("automation global detected",d.automation_keys.some(k=>k.includes("cdc")));
  ok("agent DOM marker detected",d.dom_markers.length>=1);
  ok("events counted (mouse>=2, synthetic untrusted)",d.mouse_moves>=2&&d.synthetic_events>=1);
  run("init mode (static page)",{fetchJson:{t:"p-x-1111111111",vid:"x",rx:"(copilot)",sel:[],comment:"TODO pass=TF-x-aa",hidden:'<a href="/_at/c/h-x-1">a</a>',notice:"<div>NOTICE</div>"}},(n2,w2,b2)=>{
    console.log(n2);
    ok("bait injected into DOM",w2.document.querySelector(".at-x")&&w2.document.querySelector(".at-x a"));
    ok("comment node injected",[...w2.document.body.childNodes].some(x=>x.nodeType===8&&x.data.includes("TF-x-aa")));
    ok("beacon sent",b2.length===1&&b2[0][1].t==="p-x-1111111111");
    console.log(fails?"JS FAILURES":"JS probe OK");process.exit(fails?1:0);
  });
});
