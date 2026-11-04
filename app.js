'use strict';
/* 快鲸 Web · AES-128-CFB128 + XOR 0x88 + filter */
function gfMul(a,b){let p=0;for(let i=0;i<8;i++){if(b&1)p^=a;a=(a<<1)^((a&0x80)?0x11b:0);a&=0xff;b>>=1;}return p;}
const SBOX=(()=>{const sb=new Uint8Array(256),inv=new Uint8Array(256);
for(let a=1;a<256;a++)for(let b=1;b<256;b++)if(gfMul(a,b)===1){inv[a]=b;break;}
for(let i=0;i<256;i++){const b=inv[i];sb[i]=(b^((b<<1|b>>>7)&0xff)^((b<<2|b>>>6)&0xff)^((b<<3|b>>>5)&0xff)^((b<<4|b>>>4)&0xff)^0x63)&0xff;}return sb;})();
const RCON=[0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36];
function expandKey(key){
  const rk=new Uint8Array(176);
  for(let i=0;i<16;i++)rk[i]=key[i];
  for(let w=4;w<44;w++){
    let t0=rk[(w-1)*4],t1=rk[(w-1)*4+1],t2=rk[(w-1)*4+2],t3=rk[(w-1)*4+3];
    if(w%4===0){const tmp=t0;t0=SBOX[t1]^RCON[w/4-1];t1=SBOX[t2];t2=SBOX[t3];t3=SBOX[tmp];}
    rk[w*4]=rk[(w-4)*4]^t0;rk[w*4+1]=rk[(w-4)*4+1]^t1;rk[w*4+2]=rk[(w-4)*4+2]^t2;rk[w*4+3]=rk[(w-4)*4+3]^t3;
  }
  return rk;
}
function encryptBlock(input,rk){
  let s=new Uint8Array(16);
  for(let i=0;i<16;i++)s[i]=input[i]^rk[i];
  for(let round=1;round<=9;round++){
    for(let i=0;i<16;i++)s[i]=SBOX[s[i]];
    const t=new Uint8Array(s);
    s[1]=t[5];s[5]=t[9];s[9]=t[13];s[13]=t[1];
    s[2]=t[10];s[6]=t[14];s[10]=t[2];s[14]=t[6];
    s[3]=t[15];s[7]=t[3];s[11]=t[7];s[15]=t[11];
    const o=new Uint8Array(16);
    for(let c=0;c<4;c++){
      const a0=s[c*4],a1=s[c*4+1],a2=s[c*4+2],a3=s[c*4+3];
      o[c*4]=gfMul(a0,2)^gfMul(a1,3)^a2^a3;
      o[c*4+1]=a0^gfMul(a1,2)^gfMul(a2,3)^a3;
      o[c*4+2]=a0^a1^gfMul(a2,2)^gfMul(a3,3);
      o[c*4+3]=gfMul(a0,3)^a1^a2^gfMul(a3,2);
    }
    for(let i=0;i<16;i++)o[i]^=rk[round*16+i];
    s=o;
  }
  for(let i=0;i<16;i++)s[i]=SBOX[s[i]];
  const t=new Uint8Array(s);
  s[1]=t[5];s[5]=t[9];s[9]=t[13];s[13]=t[1];
  s[2]=t[10];s[6]=t[14];s[10]=t[2];s[14]=t[6];
  s[3]=t[15];s[7]=t[3];s[11]=t[7];s[15]=t[11];
  for(let i=0;i<16;i++)s[i]^=rk[160+i];
  return s;
}
function aesCfbEncrypt(key,iv,data){
  const rk=expandKey(key),out=new Uint8Array(data.length);
  let fb=new Uint8Array(iv);
  for(let off=0;off<data.length;off+=16){
    const ks=encryptBlock(fb,rk);
    const n=Math.min(16,data.length-off);
    for(let i=0;i<n;i++)out[off+i]=data[off+i]^ks[i];
    if(n===16)fb=new Uint8Array(out.slice(off,off+16));
  }
  return out;
}
function aesCfbDecrypt(key,iv,data){
  const rk=expandKey(key),out=new Uint8Array(data.length);
  let fb=new Uint8Array(iv);
  for(let off=0;off<data.length;off+=16){
    const ks=encryptBlock(fb,rk);
    const n=Math.min(16,data.length-off);
    for(let i=0;i<n;i++)out[off+i]=data[off+i]^ks[i];
    if(n===16)fb=new Uint8Array(data.slice(off,off+16));
  }
  return out;
}
/* ===== API layer ===== */
const API_BASE='https://aaa.gqgoex.cn';
const IMG_CDN='https://pp.tplxbj.cn/';
const AES_KEY=new TextEncoder().encode('WB0nMZHXlxNndORe');
let userToken='';
function hexEnc(b){let s='';for(let i=0;i<b.length;i++)s+=b[i].toString(16).padStart(2,'0');return s;}
function hexDec(s){const b=new Uint8Array(s.length/2);for(let i=0;i<b.length;i++)b[i]=parseInt(s.substr(i*2,2),16);return b;}
function apiEncrypt(plain){
  const iv=new Uint8Array(16);
  crypto.getRandomValues(iv);
  const ct=aesCfbEncrypt(AES_KEY,iv,new TextEncoder().encode(plain));
  const h=hexEnc(ct),v=hexEnc(iv);
  return h.substring(0,16)+v+h.substring(16);
}
function apiDecrypt(t){
  let n,i,r;
  if(t.length<48){n=t.substring(0,t.length-32);i='';r=t.substring(t.length-32);}
  else{n=t.substring(0,16);i=t.substring(48);r=t.substring(16,48);}
  const raw=hexDec(n+i);
  return new TextDecoder().decode(aesCfbDecrypt(AES_KEY,hexDec(r),raw));
}
async function apiCall(path,params,method='POST'){
  const p={user_token:userToken,user_uuid:'',app_name:'android__UNI__9AB9530',app_version:'1.1.9',timestamp:Math.floor(Date.now()/1000),...params};
  const enc=apiEncrypt(JSON.stringify(p));
  const qs='data='+encodeURIComponent(enc);
  const url=method==='GET'?API_BASE+path+'?'+qs:API_BASE+path;
  const opts={method,headers:{'Content-Type':'application/x-www-form-urlencoded'}};
  if(method==='POST')opts.body=qs;
  const resp=await fetch(url,opts);
  if(!resp.ok)throw new Error('HTTP '+resp.status);
  const j=await resp.json();
  if(typeof j.data==='string'){try{j.data=JSON.parse(apiDecrypt(j.data));}catch(e){}}
  return j;
}
async function ensureLogin(){
  if(userToken)return;
  try{
    const r=await apiCall('/v2/api/user/login',{account:'r7px13',password:'855484',ac:''});
    if(r.data&&r.data.user_token)userToken=r.data.user_token;
  }catch(e){}
}
const imgCache=new Map();
const imgBusy=new Map();
const IMG_MEM_MAX=400;
function imgMemPut(url,objUrl){
  imgCache.set(url,objUrl);
  if(imgCache.size>IMG_MEM_MAX){
    const first=imgCache.keys().next().value;
    const old=imgCache.get(first);
    imgCache.delete(first);
    try{URL.revokeObjectURL(old);}catch(e){}
  }
}
async function kpFetchImage(url,signal,forceNet,store){
  const c=await kpOpen();
  if(c&&!forceNet){
    try{const hit=await c.match(url);if(hit)return hit;}catch(e){}
  }
  let resp=null,lastErr=null;
  for(let attempt=0;attempt<3;attempt++){
    if(signal&&signal.aborted)throw new DOMException('aborted','AbortError');
    try{
      resp=await fetch(url,{cache:'force-cache',signal:signal||undefined});
      if(!resp.ok)throw new Error('HTTP '+resp.status);
      break;
    }catch(e){
      lastErr=e;resp=null;
      if(e&&e.name==='AbortError')throw e;
      await new Promise(r=>setTimeout(r,400*(attempt+1)));
    }
  }
  if(!resp)throw lastErr||new Error('image fetch failed');
  if(c&&store){try{await c.put(url,resp.clone());}catch(e){}}
  return resp;
}
async function loadXorImage(url,opts){
  opts=opts||{};
  if(!opts.forceNet&&imgCache.has(url))return imgCache.get(url);
  const busy=imgBusy.get(url);
  if(busy&&!opts.forceNet)return busy;
  const p=(async()=>{
    const resp=await kpFetchImage(url,opts.signal,opts.forceNet,opts.store===true);
    const buf=await resp.arrayBuffer();
    const arr=new Uint8Array(buf);
    for(let i=0;i<arr.length;i++)arr[i]^=0x88;
    const blob=new Blob([arr],{type:'image/jpeg'});
    const objUrl=URL.createObjectURL(blob);
    imgMemPut(url,objUrl);
    return objUrl;
  })();
  imgBusy.set(url,p);
  try{return await p;}
  finally{if(imgBusy.get(url)===p)imgBusy.delete(url);}
}
function shuffle(a){for(let i=a.length-1;i>0;i--){const j=Math.floor(Math.random()*(i+1));[a[i],a[j]]=[a[j],a[i]];}return a;}
function resolveImgUrl(pic){
  if(!pic)return null;
  if(pic.startsWith('http'))return pic;
  if(pic.startsWith('/'))return IMG_CDN+pic.substring(1);
  return IMG_CDN+pic;
}
const BLOCK_STRICT=['人兽','兽交','兽奸','动物交','马交','马肛','马屌','疯马','与马','狗交','犬交','疯狗','狗屌','猪交','触手','幼女','幼交','未成年','儿童','萝莉','乱伦','男同','同性恋','gay','骚受','伪娘','肛交','爆肛','操肛','后庭','重口味','重口','猎奇','血腥','尸体','欧美','老外','洋屌','黑屌','媚黑','人妖','变性','手淫','自慰','打飞机','飞机杯','换脸','耽美'];
const BLOCK_NAME=['人兽','兽交','兽迷','兽人','兽奸','动物','动物园','动物交','幼女','幼交','未成年','乱伦','萝莉','儿童','畜生','男同','同性','同志','gay','骚受','伪娘','人妖','变性','肛交','爆肛','操肛','菊花','后庭','重口味','欧美','老外','洋屌','黑屌','媚黑','手淫','自慰','打飞机','飞机杯','疯马','马交','马肛','马屌','马鸡','野马','与马','疯狗','狗交','狗鸡','狗屌','母狗','犬交','猪射','触手','狗狗','耽美','攻受'];
const HOT_BAD=['学生','初中','高中','小学','强奸','迷奸','内射','黑料','玩偶','妈妈','母亲','父女','母子','儿子','女儿','伪娘','双胞胎'];
function isBlocked(name){ // strict filter: forum + hot words
  if(!name)return false;
  const lower=name.toLowerCase();
  return BLOCK_STRICT.some(w=>name.includes(w)||lower.includes(w.toLowerCase()));
}
function nameBlocked(name){ // looser filter: comic/vod names
  if(!name)return false;
  const lower=name.toLowerCase();
  return BLOCK_NAME.some(w=>name.includes(w)||lower.includes(w.toLowerCase()));
}
function hotBad(w){if(!w)return false;return HOT_BAD.some(b=>w.includes(b));}
/* ===== state ===== */
let mode=0;
let comicCid='',comicTid='',comicPage=1,comicEnd=false,comicKw='',comicKwMode=false;
let vodType='',vodPid='',vodPage=1,vodEnd=false,vodKw='',vodKwMode=false;
let forumBid='',forumPage=1,forumEnd=false,forumKw='',forumKwMode=false;
let loading=false,catPanelOpen=false,forumRawCount=0;
let currentComic=null;
let novelCid='',novelTid='',novelPage=1,novelEnd=false,novelKw='',novelKwMode=false;
let currentNovel=null,novelChapters=[],novelChapterIdx=-1,novelBookName='';
/* ===== external (relay) ===== */
const RELAY_BASE='https://kuaijing.liangxiaodan3.workers.dev';
let extSection=0,extKw='',extLoaded=false,extData=null;
let playerReturn='mainView';
let extPlaying=null; // {id,name,episodes:[],idx} 短剧播放上下文
/* ===== acgxmh external (relay /acg) ===== */
let currentAcg=null;
let acgOn=false,acgUrl='/',acgPage=1,acgEnd=false;
let acgSeen=new Set();
let acgRestorePage=0,acgPosTimer=0;
/* ===== view scroll memory ===== */
const KJ_VIEWS=['mainView','readerView','playerView','forumView','novelView','externalView'];
const VIEW_SCROLL={mainView:0,externalView:0};
let scrollGuardUntil=0,lastTabMode=0,extListMode=true;
const $=id=>document.getElementById(id);
const grid=$('grid'),loadMore=$('loadMore'),searchInput=$('searchInput');
const catPanel=$('catPanel'),hotChips=$('hotChips'),catClassChips=$('catClassChips'),catTagChips=$('catTagChips'),catChildChips=$('catChildChips');
const catClassRow=$('catClassRow'),catTagRow=$('catTagRow'),catChildRow=$('catChildRow');
const readerView=$('readerView'),readerList=$('readerList'),readerTitle=$('readerTitle');
const playerView=$('playerView'),videoEl=$('videoEl'),playerStatus=$('playerStatus'),playerTitle=$('playerTitle');
const forumView=$('forumView'),forumBody=$('forumBody'),forumTitle=$('forumTitle');
const novelView=$('novelView'),novelBody=$('novelBody'),novelTitle=$('novelTitle');
const toastEl=$('toast');
function showToast(msg,dur=2000){
  toastEl.textContent=msg;toastEl.classList.remove('hidden');
  clearTimeout(toastEl._t);
  toastEl._t=setTimeout(()=>toastEl.classList.add('hidden'),dur);
}
function esc(s){const d=document.createElement('div');d.textContent=s||'';return d.innerHTML;}
/* ===== tabs ===== */
document.querySelectorAll('.tab').forEach(btn=>{
  btn.addEventListener('click',()=>switchMode(parseInt(btn.dataset.mode)));
});
function switchMode(m){
  mode=m;
  if(m!==5)lastTabMode=m;
  document.querySelectorAll('.tab').forEach(b=>b.classList.toggle('active',parseInt(b.dataset.mode)===m));
  searchInput.value='';
  catPanel.classList.add('hidden');catPanelOpen=false;
  comicPage=1;comicEnd=false;comicKw='';comicKwMode=false;
  vodPage=1;vodEnd=false;vodKw='';vodKwMode=false;
  forumPage=1;forumEnd=false;forumKw='';forumKwMode=false;
  novelPage=1;novelEnd=false;novelKw='';novelKwMode=false;
  comicCid='';comicTid='';vodType='';vodPid='';forumBid='';novelCid='';novelTid='';
  acgOn=false;acgUrl='/';acgPage=1;acgEnd=false;acgSeen=new Set();
  grid.innerHTML='';
  loadMore.classList.add('hidden');
  resetMainScroll();
  syncHash(mode===5?'#/ext':'#/m/'+mode);
  if(mode===5){openExternal();return;}
  if(mode===4){renderHistory();return;}
  reloadCats();
  doLoad(true);
}
$('searchBtn').addEventListener('click',doSearch);
searchInput.addEventListener('keydown',e=>{if(e.key==='Enter')doSearch();});
function doSearch(){
  if(mode===4)return;
  const kw=searchInput.value.trim();
  if(mode===0){comicKw=kw;comicKwMode=!!kw;comicPage=1;comicEnd=false;}
  else if(mode===1){vodKw=kw;vodKwMode=!!kw;vodPage=1;vodEnd=false;}
  else if(mode===2){forumKw=kw;forumKwMode=!!kw;forumPage=1;forumEnd=false;}
  else{novelKw=kw;novelKwMode=!!kw;novelPage=1;novelEnd=false;}
  grid.innerHTML='';
  doLoad(true);
}
$('catBtn').addEventListener('click',()=>{
  catPanelOpen=!catPanelOpen;
  catPanel.classList.toggle('hidden',!catPanelOpen);
});
let comicClassesData=[],comicTagsData=[],vodTypesData=[],forumBoardsData=[];
let novelClassesData=[],novelTagsData=[];
async function reloadCats(){
  catClassChips.innerHTML='';catTagChips.innerHTML='';catChildChips.innerHTML='';
  catClassRow.classList.add('hidden');catTagRow.classList.add('hidden');catChildRow.classList.add('hidden');
  hotChips.innerHTML='';
  try{
    if(mode===0){
      catClassRow.classList.remove('hidden');catTagRow.classList.remove('hidden');
      const r=await apiCall('/v2/api/comic/condition',{},'GET');
      const d=r.data||{};
      comicClassesData=(d.class||[]).filter(c=>c.name&&c.id&&c.name!=='全部'&&!c.name.includes('欧美')&&!c.name.includes('同性')&&!nameBlocked(c.name));
      comicTagsData=(d.tags||[]).filter(t=>t.name&&t.id&&t.name!=='全部'&&!t.name.includes('欧美')&&!t.name.includes('同性')&&!nameBlocked(t.name));
      const seen=new Set();comicClassesData=comicClassesData.filter(c=>{if(seen.has(c.name))return false;seen.add(c.name);return true;});
      const seenT=new Set();comicTagsData=comicTagsData.filter(t=>{if(seenT.has(t.name))return false;seenT.add(t.name);return true;});
      buildChips(catClassChips,comicClassesData,'cid',()=>{comicCid='';});
      buildChips(catTagChips,comicTagsData,'tid',()=>{comicTid='';});
      const hr=await apiCall('/v2/api/comic/hotSearch',{},'GET');
      const hw=(hr.data&&hr.data.hot_keyword)||[];
      buildHot(hw);
      buildAcgChips(catClassChips,ACG_COMICS);
    }else if(mode===1){
      catClassRow.classList.remove('hidden');catChildRow.classList.remove('hidden');
      const r=await apiCall('/api/app/vodClass',{},'GET');
      const d=r.data||{};
      vodTypesData=(d.type||[]).filter(t=>String(t.id)&&t.name&&t.name!=='全部'&&!['4','73','8'].includes(String(t.id))&&!nameBlocked(t.name));
      buildChips(catClassChips,vodTypesData.map(t=>({id:String(t.id),name:t.name})),'vpid',()=>{vodPid='';vodType='';});
      const hr=await apiCall('/api/app/hotSearch',{},'GET');
      const hd=hr.data||[];
      let hw=[];
      if(Array.isArray(hd))for(const o of hd){const list=o.list||[];for(const k of list){const w=k.vod_name||'';if(w&&!isBlocked(w)&&!hotBad(w)){hw.push(w);if(hw.length>=20)break;}}if(hw.length>=20)break;}
      buildHot(hw);
      buildAcgChips(catClassChips,ACG_VIDEOS);
    }else if(mode===2){
      catClassRow.classList.remove('hidden');
      const r=await apiCall('/v2/api/forum/index',{id:1});
      const d=r.data||{};
      const child=(d.board&&d.board.child)||[];
      forumBoardsData=child.filter(b=>b.name&&b.name!=='全部'&&!isBlocked(b.name)).map(b=>({id:String(b.id),name:b.name}));
      buildChips(catClassChips,[{id:'0',name:'最新'},...forumBoardsData],'bid',()=>{forumBid='0';});
      try{
        const hr=await apiCall('/v2/api/forum/hotSearch',{},'GET');
        const hw=(hr.data&&hr.data.hot_keyword)||[];
        buildHot(hw);
      }catch(e){buildHot([]);}
    }else{
      catClassRow.classList.remove('hidden');catTagRow.classList.remove('hidden');
      const r=await apiCall('/v2/api/book/condition',{},'GET');
      const d=r.data||{};
      novelClassesData=(d.class||[]).filter(c=>c.name&&c.id&&c.name!=='全部'&&!novelBlocked(c.name));
      novelTagsData=(d.tags||[]).filter(t=>t.name&&t.id&&t.name!=='全部'&&!novelBlocked(t.name));
      buildChips(catClassChips,novelClassesData,'ncid',()=>{novelCid='';});
      buildChips(catTagChips,novelTagsData,'ntid',()=>{novelTid='';});
      try{
        const hr=await apiCall('/v2/api/book/hotSearch',{},'GET');
        const hw=(hr.data&&hr.data.hot_keyword)||[];
        buildHot(hw);
      }catch(e){buildHot([]);}
    }
  }catch(e){}
}
function buildChips(container,items,key,clearFn){
  container.innerHTML='';
  const all=document.createElement('span');
  all.className='chip active';all.textContent='全部';
  all.addEventListener('click',()=>{
    container.querySelectorAll('.chip').forEach(c=>c.classList.remove('active'));
    all.classList.add('active');
    clearFn();
    acgOn=false;acgUrl='/';acgPage=1;acgEnd=false;acgSeen=new Set();
    if(key==='cid')comicCid='';
    if(key==='tid')comicTid='';
    if(key==='vpid'){vodPid='';vodType='';catChildChips.innerHTML='';}
    if(key==='bid')forumBid='';
    if(key==='ncid')novelCid='';
    if(key==='ntid')novelTid='';
    doLoad(true);
  });
  container.appendChild(all);
  for(const item of items){
    const chip=document.createElement('span');
    chip.className='chip';chip.textContent=item.name;
    chip.addEventListener('click',()=>{
      container.querySelectorAll('.chip').forEach(c=>c.classList.remove('active'));
      chip.classList.add('active');
      acgOn=false;acgUrl='/';acgPage=1;acgEnd=false;acgSeen=new Set();
      if(key==='cid'){comicCid=item.id;comicTid='';catTagChips.querySelectorAll('.chip').forEach(c=>c.classList.remove('active'));catTagChips.firstElementChild.classList.add('active');}
      if(key==='tid')comicTid=item.id;
      if(key==='vpid'){
        vodPid=item.id;vodType='';
        catChildChips.innerHTML='';
        const parent=vodTypesData.find(t=>String(t.id)===item.id);
        if(parent&&parent.child&&parent.child.length){
          const ac=document.createElement('span');ac.className='chip active';ac.textContent='全部';
          ac.addEventListener('click',()=>{vodType='';catChildChips.querySelectorAll('.chip').forEach(c=>c.classList.remove('active'));ac.classList.add('active');doLoad(true);});
          catChildChips.appendChild(ac);
          for(const ch of parent.child){
            const c=document.createElement('span');c.className='chip';c.textContent=ch.name;
            c.addEventListener('click',()=>{
              catChildChips.querySelectorAll('.chip').forEach(x=>x.classList.remove('active'));
              c.classList.add('active');vodType=String(ch.id);doLoad(true);
            });
            catChildChips.appendChild(c);
          }
        }
      }
      if(key==='bid')forumBid=item.id==='0'?'':item.id;
      if(key==='ncid'){novelCid=item.id;novelTid='';catTagChips.querySelectorAll('.chip').forEach(c=>c.classList.remove('active'));catTagChips.firstElementChild.classList.add('active');}
      if(key==='ntid')novelTid=item.id;
      doLoad(true);
    });
    container.appendChild(chip);
  }
}
function buildHot(words){
  hotChips.innerHTML='';
  for(const w of words){
    if(!w||isBlocked(w)||hotBad(w))continue;
    const chip=document.createElement('span');
    chip.className='chip';chip.textContent=w;
    chip.addEventListener('click',()=>{searchInput.value=w;doSearch();});
    hotChips.appendChild(chip);
  }
}
async function doLoad(reset){
  if(loading)return;
  loading=true;
  loadMore.classList.remove('hidden');
  loadMore.textContent='加载中...';
  try{
    let items=[];
    if((mode===0||mode===1)&&acgOn){
      const want=mode===0?'c':'v';
      const out=[];
      let guard=0;
      while(out.length<36&&!acgEnd&&guard<6){
        const d=await acgFetchList(acgUrl,acgPage);
        const arr=d.items||d.list||[];
        for(const it of arr){
          const key=String(it.id||it.url||it.h||'');
          if(key&&acgSeen.has(key))continue;
          if(key)acgSeen.add(key);
          const isVid=(it.type==='v'||it.seg==='gif');
          if(want==='v'?isVid:!isVid)out.push(it);
        }
        if(!arr.length||acgPage>200)acgEnd=true;else acgPage++;
        guard++;
      }
      if(reset)grid.innerHTML='';
      if(!out.length&&reset)grid.innerHTML='<div class="acgEmpty">暂无作品·换个分类试试</div>';
      for(const it of out)renderAcgCard(it);
      return;
    }
    if(mode===0){
      let raw1=[];
      if(comicKwMode){
        const r1=await apiCall('/v2/api/comic/searchList',{wd:comicKw,page:comicPage});
        raw1=(r1.data||{}).list||[];
      }else{
        const r1=await apiCall('/v2/api/comic/list',{page:comicPage,cid:comicCid,tid:comicTid,sort:'rand'});
        raw1=(r1.data||{}).list||[];
      }
      items=raw1.filter(c=>c.name&&!nameBlocked(c.name));
      if(raw1.length<12)comicEnd=true;
    }else if(mode===1){
      let raw2=[];
      if(vodKwMode){
        const r2=await apiCall('/api/app/searchList',{wd:vodKw,page:vodPage});
        raw2=(r2.data||{}).list||[];
      }else{
        const r2=await apiCall('/api/app/vodList',{type:vodType,type_pid:vodPid,class:'',sort:'',page:1+Math.floor(Math.random()*60)});
        raw2=shuffle((r2.data||{}).list||[]);
      }
      items=raw2.filter(v=>v.vod_name&&!nameBlocked(v.vod_name)&&v.type_id!==4);
      if(raw2.length<10)vodEnd=true;
    }else if(mode===2){
      if(forumKwMode){
        const r3=await apiCall('/v2/api/forum/searchList',{wd:forumKw,page:forumPage});
        items=parseForumList(r3);
      }else{
        const r3=await apiCall('/v2/api/forum/list',{bid:forumBid,uid:'',type:'',page:forumPage});
        items=parseForumList(r3);
      }
      if(forumRawCount<10)forumEnd=true;
    }else{
      let raw4=[];
      if(novelKwMode){
        const r4=await apiCall('/v2/api/book/searchList',{wd:novelKw,page:novelPage});
        raw4=(r4.data||{}).list||[];
      }else{
        const r4=await apiCall('/v2/api/book/list',{page:novelPage,cid:novelCid,tid:novelTid,sort:'rand'});
        raw4=(r4.data||{}).list||[];
      }
      items=raw4.filter(b=>b.name&&!novelBlocked(b.name));
      if(raw4.length<12)novelEnd=true;
    }
    if(reset)grid.innerHTML='';
    renderItems(items);
    if(reset&&((mode===0&&comicKwMode)||(mode===1&&vodKwMode))){try{await appendAcgSearch();}catch(e){}}
  }catch(e){
    if(reset)grid.innerHTML='';
    showToast('加载失败: '+e.message);
  }finally{
    loading=false;
    if(acgOn&&(mode===0||mode===1)){
      loadMore.textContent=acgEnd?'没有更多了':'';
      if(!acgEnd)loadMore.classList.add('hidden');
    }else if((mode===0&&comicEnd)||(mode===1&&vodEnd)||(mode===2&&forumEnd)||(mode===3&&novelEnd)){
      loadMore.textContent='没有更多了';
    }else{
      loadMore.classList.add('hidden');
    }
  }
}
function parseForumList(r){
  const d=r.data||{};
  const list=d.list||[];
  forumRawCount=list.length;
  const out=[];
  for(const o of list){
    const title=o.posts_title||'';
    const board=o.board_name||'';
    if(isBlocked(title)||isBlocked(board))continue;
    let cover='';
    const pics=o.posts_pic||[];
    for(const p of pics){if(p){cover=p;break;}}
    out.push({
      id:o.posts_id,type:o.posts_type||1,title,boardName:board,
      hits:o.posts_hits||0,liked:o.posts_liked||0,cover,
      author:o.user_nick_name||o.user_name||'',
      picCount:(o.posts_pic||[]).length
    });
  }
  return out;
}
function renderItems(items){
  for(const item of items){
    if(mode===0)renderComicCard(item);
    else if(mode===1)renderVodCard(item);
    else if(mode===2)renderForumCard(item);
    else renderNovelCard(item);
  }
}
function renderComicCard(c){
  const div=document.createElement('a');
  div.className='card';
  div.href=mkHref('c',c.id,c.name,0);
  const coverUrl=resolveImgUrl(c.pic);
  div.innerHTML='<div class="cover"><span>\uD83D\uDCD6</span>'+(c.pay===2?'<span class="badge">VIP</span>':'')+'</div>'+
    '<div class="info"><div class="name">'+esc(c.name)+'</div><div class="sub">'+(c.latest_chapter_name?'更新至 '+esc(c.latest_chapter_name):'连载中')+'</div></div>';
  div.addEventListener('click',e=>{
    if(e.metaKey||e.ctrlKey||e.shiftKey||e.altKey||e.button!==0)return;
    e.preventDefault();
    navTo(div.getAttribute('href'),()=>openComic(c));
  });
  grid.appendChild(div);
  if(coverUrl)lazyImg(div.querySelector('.cover'),coverUrl);
}
function renderVodCard(v){
  const div=document.createElement('a');
  div.className='card';
  div.href=mkHref('v',v.vod_id,v.vod_name,1);
  const coverUrl=resolveImgUrl(v.vod_pic);
  const hd=v.vod_mode?'HD':'';
  div.innerHTML='<div class="cover"><span>\uD83C\uDFAC</span>'+(hd?'<span class="badge">'+hd+'</span>':'')+(v.vod_duration?'<span class="dur">'+esc(v.vod_duration)+'</span>':'')+'</div>'+
    '<div class="info"><div class="name">'+esc(v.vod_name)+'</div><div class="sub">'+(v.vod_duration?'时长 '+esc(v.vod_duration):'')+'</div></div>';
  div.addEventListener('click',e=>{
    if(e.metaKey||e.ctrlKey||e.shiftKey||e.altKey||e.button!==0)return;
    e.preventDefault();
    navTo(div.getAttribute('href'),()=>openVod(v));
  });
  grid.appendChild(div);
  if(coverUrl)lazyImg(div.querySelector('.cover'),coverUrl);
}
function renderForumCard(f){
  const div=document.createElement('a');
  div.className='card';
  div.href=mkHref('f',f.id,f.title,2);
  const coverUrl=f.cover?resolveImgUrl(f.cover):null;
  div.innerHTML='<div class="cover"><span>\uD83D\uDCAC</span></div>'+
    '<div class="info"><div class="name">'+esc(f.title)+'</div><div class="sub">'+esc(f.boardName)+' · '+f.hits+'阅</div></div>';
  div.addEventListener('click',e=>{
    if(e.metaKey||e.ctrlKey||e.shiftKey||e.altKey||e.button!==0)return;
    e.preventDefault();
    navTo(div.getAttribute('href'),()=>openForum(f));
  });
  grid.appendChild(div);
  if(coverUrl)lazyImg(div.querySelector('.cover'),coverUrl);
}
function lazyImg(container,url){
  loadXorImage(url).then(objUrl=>{
    const img=container.querySelector('img');
    if(img){img.src=objUrl;img.style.display='';}
    else{
      const i=document.createElement('img');
      i.src=objUrl;i.alt='';
      container.insertBefore(i,container.firstChild);
    }
    const sp=container.querySelector('span');
    if(sp)sp.style.display='none';
  }).catch(()=>{});
}
/* ===== acgxmh external (relay /acg) ===== */
const ACG_COMICS=[
  {name:'外站·首页',url:'/'},
  {name:'外站·丝袜',url:'/tags/stockings.html'},
  {name:'外站·女仆',url:'/tags/maid.html'},
  {name:'外站·眼镜',url:'/tags/glasses.html'},
  {name:'外站·巨乳',url:'/tags/huge-breasts.html'},
  {name:'外站·全彩',url:'/tags/full-color.html'},
  {name:'外站·汉化',url:'/tags/chinese.html'},
  {name:'外站·无码',url:'/tags/uncensored.html'},
  {name:'外站·熟女',url:'/tags/milf.html'}
];
const ACG_VIDEOS=[
  {name:'外站·3D',url:'/tags/_3_d.html'},
  {name:'外站·长视频',url:'/tags/stocking.html'},
  {name:'外站·cosplay',url:'/tags/cosplay.html'},
  {name:'外站·制服',url:'/tags/school-uniform.html'}
];
function acgListUrl(u,p){return RELAY_BASE+'/acg/list?u='+encodeURIComponent(u)+'&p='+p;}
async function acgFetchList(u,p){
  const r=await fetch(acgListUrl(u,p),{cache:'no-store'});
  if(!r.ok)throw new Error('HTTP '+r.status);
  const d=await r.json();
  if(d&&d.error)throw new Error(String(d.error));
  return d;
}
function buildAcgChips(container,items){
  const lab=document.createElement('span');
  lab.className='acgLabel';lab.textContent='外站';
  container.appendChild(lab);
  for(const it of items){
    const chip=document.createElement('span');
    chip.className='chip acg';chip.textContent=it.name;
    chip.addEventListener('click',()=>{
      container.querySelectorAll('.chip').forEach(c=>c.classList.remove('active'));
      chip.classList.add('active');
      acgOn=true;acgUrl=it.url;acgPage=1;acgEnd=false;acgSeen=new Set();
      comicKw='';comicKwMode=false;vodKw='';vodKwMode=false;
      grid.innerHTML='';
      resetMainScroll();
      doLoad(true);
    });
    container.appendChild(chip);
  }
}
function renderAcgCard(it){
  const div=document.createElement('a');
  div.className='card';
  const seg=it.seg||'h';
  const isVid=(it.type==='v'||seg==='gif');
  div.href=mkHref('a',it.id,it.title,lastTabMode)+'&s='+encodeURIComponent(seg);
  div.innerHTML='<div class="cover"><span>'+(isVid?'\u25B6':'\uD83D\uDCD6')+'</span><span class="badge">外站</span></div>'+
    '<div class="info"><div class="name">'+esc(it.title||'')+'</div><div class="sub">'+esc((it.cat||'')+(it.time?' · '+it.time:''))+'</div></div>';
  div.addEventListener('click',e=>{
    if(e.metaKey||e.ctrlKey||e.shiftKey||e.altKey||e.button!==0)return;
    e.preventDefault();
    navTo(div.getAttribute('href'),()=>openAcgComic(it));
  });
  grid.appendChild(div);
  if(it.cover){
    const cov=div.querySelector('.cover');
    const img=document.createElement('img');
    img.loading='lazy';img.alt='';img.referrerPolicy='no-referrer';
    img.onerror=()=>{img.onerror=null;img.src=RELAY_BASE+'/acg/img?u='+encodeURIComponent(it.cover);};
    img.src=RELAY_BASE+'/acg/img?u='+encodeURIComponent(it.cover);
    cov.insertBefore(img,cov.firstChild);
    const sp=cov.querySelector('span');
    if(sp)sp.style.display='none';
  }
}
function openAcgComic(it){
  kpStop();
  currentComic=null;
  currentTg=null;
  currentAcg=it;
  recordHistory('acg',it);
  const _p0=posOf('a'+it.id);acgRestorePage=_p0?(_p0.page||0):0;
  readerTitle.textContent=it.title||'';
  readerList.innerHTML='<div class="loadingHint">加载中...</div>';
  showView('readerView');
  setupReaderScroll();
  loadAcgPages(it);
}
async function loadAcgPages(it){
  if((it.seg||'')==='tgc'){loadTgComic(it);return;}
  try{
    const seg=it.seg||'h';
    const isVid=(it.type==='v'||seg==='gif');
    const u='/'+seg+'/'+it.id+'.html';
    const t=isVid?'g':'c';
    let r=await fetch(RELAY_BASE+'/acg/detail?u='+encodeURIComponent(u)+'&id='+encodeURIComponent(it.id)+'&t='+t,{cache:'no-store'});
    if(!r.ok)throw new Error('HTTP '+r.status);
    let d=await r.json();
    if(d.error)throw new Error(d.error);
    let pages=d.pages||[];
    if(!isVid&&!pages.length&&d.m3u8){
      openAcgPlay(RELAY_BASE+'/acg/hls?u='+encodeURIComponent(d.m3u8),d.name||it.title);
      return;
    }
    const totalN=parseInt(d.total,10)||pages.length||0;
    if(!isVid&&(d.dynamic||pages.length<totalN)&&totalN>1){
      if(pages.length>totalN)pages.length=totalN;
      const need=[];
      for(let i=pages.length?Math.max(2,pages.length+1):1;i<=totalN;i++)need.push(i);
      for(let k=0;k<need.length;k+=6){
        const batch=need.slice(k,k+6);
        const got=await Promise.all(batch.map(async pn=>{
          try{
            const r2=await fetch(RELAY_BASE+'/acg/page?u='+encodeURIComponent(u)+'&t=c&p='+pn,{cache:'no-store'});
            const d2=await r2.json();
            return d2&&d2.img?d2.img:'';
          }catch(e){return '';}
        }));
        for(const g of got)if(g&&pages.indexOf(g)<0)pages.push(g);
      }
    }
    if(isVid){
      const play=d.play||(d.m3u8?('/acg/hls?u='+encodeURIComponent(d.m3u8)):'');
      if(!play)throw new Error('无播放地址');
      openAcgPlay(RELAY_BASE+play,d.name||it.title);
      return;
    }
    if(!pages.length){readerList.innerHTML='<div class="loadingHint">该作品无图片</div>';return;}
    readerList.innerHTML='';
    const total=pages.length;
    const nm=d.name||it.title||'';
    let loaded=0;
    readerTitle.textContent=nm+' ('+total+'页)';
    for(const url of pages){
      const img=document.createElement('img');
      img.alt='';img.className='acgPage';img.referrerPolicy='no-referrer';
      readerList.appendChild(img);
      setImg(img,url,()=>{loaded++;readerTitle.textContent=nm+' ('+loaded+'/'+total+')';});
    }
    if(acgRestorePage>0){const _rp=acgRestorePage;acgRestorePage=0;restoreScrollTo(readerList,_rp);}
  }catch(e){
    readerList.innerHTML='<div class="loadingHint">加载失败: '+esc(e.message)+'</div>';
  }
}
function openAcgPlay(hlsUrl,title){
  playerReturn='acgReader';
  plSetNavVisible(false);
  playerTitle.textContent=title||'';
  playerStatus.textContent='';
  showView('playerView');
  plPlay(hlsUrl);
}
async function appendAcgSearch(){
  const kw=mode===0?comicKw:vodKw;
  if(!kw)return;
  let d;
  try{
    const r=await fetch(RELAY_BASE+'/acg/find?kw='+encodeURIComponent(kw),{cache:'no-store'});
    if(!r.ok)return;
    d=await r.json();
  }catch(e){return;}
  if(!d||d.error)return;
  const topics=[];
  if(d.hit&&d.hit.h)topics.push(d.hit.h);
  for(const o of (d.list||[])){if(o&&o.h&&topics.indexOf(o.h)<0)topics.push(o.h);}
  const seen={};
  const out=[];
  for(const u of topics.slice(0,5)){
    try{
      const li=await acgFetchList(u,1);
      for(const it of (li.items||[])){
        if(seen[it.id])continue;
        const isVid=(it.type==='v'||it.seg==='gif');
        if(mode===0&&isVid)continue;
        if(mode===1&&!isVid)continue;
        seen[it.id]=1;out.push(it);
        if(out.length>=36)break;
      }
    }catch(e){}
    if(out.length>=36)break;
  }
  if(!out.length)return;
  const sep=document.createElement('div');
  sep.className='acgSep';sep.textContent='外站结果 · '+out.length+' 部';
  grid.appendChild(sep);
  for(const it of out)renderAcgCard(it);
  try{
    const td=await tgGet('/tg/search?kw='+encodeURIComponent(kw)+'&p=1');
    const arr=[];
    for(const v of (td.comics||[]))arr.push({type:'m',id:v.id,title:v.title,cover:v.cover});
    for(const v of (td.videos||[]))if(mode===1)arr.push({type:'v',id:v.id,title:v.title,cover:v.cover});
    for(const v of (td.posts||[]))if(mode===1)arr.push({type:'p',id:v.id,title:v.title,cover:v.cover});
    const use=arr.filter(x=>x.title&&!nameBlocked(x.title)).slice(0,18);
    if(use.length){
      const s2=document.createElement('div');
      s2.className='acgSep';s2.textContent='热瓜 · '+use.length+' 部';
      grid.appendChild(s2);
      for(const it of use)tgCard(it,grid);
    }
  }catch(e){}
}
/* ===== infinite scroll ===== */
function onInfiniteScroll(){
  if(Date.now()<scrollGuardUntil)return;
  if($('mainView').classList.contains('hidden'))return;
  if(mode===4)return;
  if(loading)return;
  if(acgOn&&(mode===0||mode===1)&&acgEnd)return;
  if((mode===0&&comicEnd)||(mode===1&&vodEnd)||(mode===2&&forumEnd)||(mode===3&&novelEnd))return;
  const se=document.scrollingElement||document.documentElement;
  if(se.scrollTop+se.clientHeight>=se.scrollHeight-400){
    if(mode===0){if(acgOn)doLoad(false);else{comicPage++;doLoad(false);}}
    else if(mode===1){if(acgOn)doLoad(false);else{vodPage++;doLoad(false);}}
    else if(mode===2){forumPage++;doLoad(false);}
    else{novelPage++;doLoad(false);}
  }
}
window.addEventListener('scroll',onInfiniteScroll,{passive:true});
document.addEventListener('scroll',onInfiniteScroll,{passive:true});
/* ===== comic reader ===== */
let chaptersCache=[],loadedChapters=[],currentChapterIdx=-1,loadingChapter=false;
let pendingRestore=0,restoreTries=0,restoringPos=false,posTimer=0;
async function openComic(comic){
  kpStop();
  currentAcg=null;
  currentTg=null;
  currentComic=comic;
  recordHistory('comic',comic);
  readerTitle.textContent=comic.name;
  readerList.innerHTML='<div class="loadingHint">加载章节...</div>';
  showView('readerView');
  try{
    await ensureLogin();
    const r=await apiCall('/v2/api/comic/chapter',{mid:comic.id,id:''});
    const d=r.data||{};
    chaptersCache=(d.chapter||[]).map(c=>({id:c.id,name:c.name,pay:c.pay||0,bullion:c.bullion||0}));
    await kpIndex();
    renderChapterButtons();
    if(chaptersCache.length>0){
      const pos=posOf(comic.id);
      let target=chaptersCache[0];
      if(pos&&pos.cid){const f=chaptersCache.find(c=>String(c.id)===String(pos.cid));if(f)target=f;}
      pendingRestore=(pos&&String(pos.cid)===String(target.id))?(pos.page||0):0;
      loadChapterPages(target.id,target.name,target.pay);
    }
    else readerList.innerHTML='<div class="loadingHint">无章节</div>';
  }catch(e){
    readerList.innerHTML='<div class="loadingHint">加载失败: '+esc(e.message)+'</div>';
  }
}
function renderChapterButtons(){
  const list=$('chapterList');
  list.innerHTML='';
  const cid=currentComic&&currentComic.id;
  for(const ch of chaptersCache){
    const btn=document.createElement('button');
    btn.className='chapterItem';
    btn.dataset.cid=ch.id;
    btn.textContent=ch.name+(ch.pay!==0?' \u{1F512}':'');
    const mk=document.createElement('span');
    mk.className='kpMark';
    btn.appendChild(mk);
    btn.addEventListener('click',()=>{pendingRestore=0;closeChapterPanel();loadChapterPages(ch.id,ch.name,ch.pay);});
    list.appendChild(btn);
  }
  refreshChapterMarks();
}
async function refreshChapterMarks(){
  const cid=currentComic&&currentComic.id;
  if(cid==null)return;
  const m=await kpIndex();
  const btns=document.querySelectorAll('#chapterList .chapterItem');
  for(let i=0;i<btns.length;i++){
    const btn=btns[i];
    const mk=btn.querySelector('.kpMark');
    if(!mk)continue;
    mk.textContent=m.has(String(cid)+'|'+String(btn.dataset.cid))?' \u2B07':'';
  }
}
async function loadChapterPages(cid,cname,pay){
  if(loadingChapter)return;
  loadingChapter=true;
  kpStop();
  readerList.innerHTML='<div class="loadingHint">加载中...</div>';
  loadedChapters=[];
  currentChapterIdx=chaptersCache.findIndex(c=>c.id===cid);
  try{
    const hit=await kpChapter(currentComic&&currentComic.id,cid);
    const pages=(hit&&hit.urls&&hit.urls.length)?hit.urls.slice():await getChapterPages({id:cid,name:cname,pay:pay});
    if(pages.length===0){readerList.innerHTML='<div class="loadingHint">该章节无图片数据</div>';loadingChapter=false;return;}
    const chapterDiv=document.createElement('div');
    chapterDiv.innerHTML='<div class="chapterDivider">'+esc(cname)+'</div>';
    readerList.appendChild(chapterDiv);
    const container=document.createElement('div');
    chapterDiv.appendChild(container);
    let loaded=0;
    for(const url of pages){
      const img=document.createElement('img');
      img.alt='';
      container.appendChild(img);
      setImg(img,url,()=>{
        loaded++;
        readerTitle.textContent=cname+' ('+loaded+'/'+pages.length+')';
      });
    }
    loadedChapters.push({id:cid,name:cname,pay,element:chapterDiv,total:pages.length});
    readerTitle.textContent=cname;
    setupReaderScroll();
    if(pendingRestore>0){const rp=pendingRestore;pendingRestore=0;restoreScrollTo(container,rp);}
    kpSchedule();
    saveReaderPos();
  }catch(e){
    readerList.innerHTML='<div class="loadingHint">加载失败: '+esc(e.message)+'</div>';
  }finally{loadingChapter=false;}
}
function parseImgList(imglist,cdn){
  if(!imglist)return[];
  let base=cdn||IMG_CDN;
  if(!base.endsWith('/'))base+='/';
  const out=[];
  for(const part of imglist.split('###')){
    if(!part)continue;
    if(part.startsWith('http'))out.push(part);
    else out.push(base+part);
  }
  return out;
}
async function enumeratePages(firstPath,cdn,signal){
  let base=cdn||IMG_CDN;
  if(!base.endsWith('/'))base+='/';
  let dir='';
  if(firstPath){
    if(firstPath.startsWith('http')){const i=firstPath.lastIndexOf('/');if(i>=0)dir=firstPath.substring(0,i+1);}
    else{const i=firstPath.lastIndexOf('/');dir=i>=0?base+firstPath.substring(0,i+1):base;}
  }
  if(!dir)return firstPath?[firstPath]:[];
  const maxPage=400,batch=80;
  const results=[];
  let scanStart=1,keep=true;
  while(keep&&scanStart<=maxPage){
    if(signal&&signal.aborted)throw new DOMException('aborted','AbortError');
    const lo=scanStart,hi=Math.min(maxPage,scanStart+batch-1);
    const probes=[];
    for(let n=lo;n<=hi;n++)probes.push(probePage(dir,n,signal));
    const settled=await Promise.allSettled(probes);
    let found=0;
    for(let i=0;i<settled.length;i++){
      if(settled[i].status==='fulfilled'&&settled[i].value){results.push({n:lo+i,url:settled[i].value});found++;}
    }
    if(found===0)keep=false;
    scanStart+=batch;
    if(hi>=maxPage)keep=false;
  }
  if(signal&&signal.aborted)throw new DOMException('aborted','AbortError');
  if(results.length===0)return firstPath?[firstPath]:[];
  results.sort((a,b)=>a.n-b.n);
  return results.map(r=>r.url);
}
async function probePage(dir,n,signal){
  for(const suffix of ['_c_xfile.jpg','_xfile.jpg']){
    if(signal&&signal.aborted)return null;
    const url=dir+n+suffix;
    try{
      const resp=await fetch(url,{headers:{'Range':'bytes=0-3'},signal:signal||undefined});
      if(resp.status===200||resp.status===206){
        const buf=await resp.arrayBuffer();
        const arr=new Uint8Array(buf);
        if(arr.length>=2&&(arr[0]^0x88)===0xff&&(arr[1]^0x88)===0xd8)return url;
      }
    }catch(e){}
  }
  return null;
}
function setupReaderScroll(){
  if(currentTg){setupTgReaderScroll();return;}
  if(currentAcg){readerList.onscroll=()=>{if(restoringPos)return;saveAcgPos();};return;}
  readerList.onscroll=()=>{
    if(restoringPos){return;}
    if(loadingChapter)return;
    if(readerList.scrollTop+readerList.clientHeight>=readerList.scrollHeight-200){
      const next=chaptersCache[currentChapterIdx+1];
      if(next&&!loadedChapters.find(c=>c.id===next.id))appendNextChapter(next);
    }
    if(readerList.scrollTop<10&&currentChapterIdx>0){
      const prev=chaptersCache[currentChapterIdx-1];
      if(prev&&!loadedChapters.find(c=>c.id===prev.id))prependPrevChapter(prev);
    }
    saveReaderPos();
  };
}
async function appendNextChapter(ch){
  if(loadingChapter)return;
  loadingChapter=true;
  const hint=document.createElement('div');
  hint.className='loadingHint';hint.textContent='加载下一章...';
  readerList.appendChild(hint);
  currentChapterIdx++;
  try{
    const hit=await kpChapter(currentComic&&currentComic.id,ch.id);
    const pages=(hit&&hit.urls&&hit.urls.length)?hit.urls.slice():await getChapterPages(ch);
    hint.remove();
    if(pages.length===0){loadingChapter=false;return;}
    const chapterDiv=document.createElement('div');
    chapterDiv.innerHTML='<div class="chapterDivider">'+esc(ch.name)+'</div>';
    const container=document.createElement('div');
    chapterDiv.appendChild(container);
    readerList.appendChild(chapterDiv);
    for(const url of pages){
      const img=document.createElement('img');img.alt='';
      container.appendChild(img);
      setImg(img,url);
    }
    loadedChapters.push({id:ch.id,name:ch.name,pay:ch.pay,element:chapterDiv,total:pages.length});
    readerTitle.textContent=ch.name;
    kpSchedule();
  }catch(e){hint.textContent='加载失败';}
  loadingChapter=false;
}
async function prependPrevChapter(ch){
  if(loadingChapter)return;
  loadingChapter=true;
  const hint=document.createElement('div');
  hint.className='loadingHint';hint.textContent='加载上一章...';
  readerList.prepend(hint);
  currentChapterIdx--;
  try{
    const hit=await kpChapter(currentComic&&currentComic.id,ch.id);
    const pages=(hit&&hit.urls&&hit.urls.length)?hit.urls.slice():await getChapterPages(ch);
    hint.remove();
    if(pages.length===0){loadingChapter=false;return;}
    const oldH=readerList.scrollHeight;
    const chapterDiv=document.createElement('div');
    chapterDiv.innerHTML='<div class="chapterDivider">'+esc(ch.name)+'</div>';
    const container=document.createElement('div');
    chapterDiv.appendChild(container);
    const imgs=[];
    for(const url of pages){
      const img=document.createElement('img');img.alt='';
      container.appendChild(img);imgs.push(img);
      setImg(img,url);
    }
    readerList.prepend(chapterDiv);
    loadedChapters.unshift({id:ch.id,name:ch.name,pay:ch.pay,element:chapterDiv});
    Promise.all(imgs.map(img=>new Promise(res=>{
      if(img.complete)res();else{img.onload=res;img.onerror=res;}
    }))).then(()=>{
      requestAnimationFrame(()=>{
        const newH=readerList.scrollHeight;
        readerList.scrollTop=newH-oldH;
      });
    });
    readerTitle.textContent=ch.name;
    kpSchedule();
  }catch(e){hint.textContent='加载失败';}
  loadingChapter=false;
}
async function getChapterPages(ch,opts){
  opts=opts||{};
  await ensureLogin();
  const mid=opts.comicId||(currentComic&&currentComic.id);
  const r=await apiCall('/v2/api/comic/chapter',{mid:mid,id:ch.id});
  const d=r.data||{};
  let imglist='',domain=d.domain||IMG_CDN,auth=!!(d.data&&d.data.auth);
  if(d.data)imglist=d.data.imglist||'';
  if(!auth&&ch.pay!==0){
    let br=await apiCall('/v2/api/comic/buy',{id:ch.id});
    if(!(br.code===1&&br.data&&br.data.imglist)){userToken='';await ensureLogin();br=await apiCall('/v2/api/comic/buy',{id:ch.id});}
    if(br.code===1&&br.data&&br.data.imglist){imglist=br.data.imglist;auth=true;}
  }
  let pages=parseImgList(imglist,domain);
  if(pages.length<=1&&!auth&&!opts.noEnumerate)pages=await enumeratePages(pages[0]||imglist,domain,opts.signal);
  return pages;
}
let readerLandscape=false;
let readerDeg=0;
let readerZoom=0;
try{readerDeg=parseInt(localStorage.getItem('kj-rot')||'0',10)||0;}catch(e){readerDeg=0;}
try{readerZoom=parseInt(localStorage.getItem('kj-zoom')||'0',10)||0;}catch(e){readerZoom=0;}
if(!readerZoom)readerZoom=(window.innerWidth>=900?80:100);
function applyReaderZoom(){
  const z=Math.max(40,Math.min(150,readerZoom||100));
  readerZoom=z;
  const list=$('readerList');if(list)list.style.setProperty('--zoom',String(z));
  const zv=$('zoomVal');if(zv)zv.textContent=z+'%';
  const zr=$('zoomRange');if(zr)zr.value=String(z);
  const btns=document.querySelectorAll('#zoomPresets button');
  for(let i=0;i<btns.length;i++)btns[i].classList.toggle('active',btns[i].dataset.z===String(z));
  try{localStorage.setItem('kj-zoom',String(z));}catch(e){}
}
function closeChapterPanel(){$('chapterPanel').classList.add('hidden');}
function openChapterPanel(){$('chapterPanel').classList.remove('hidden');}
$('readerCatalog').addEventListener('click',()=>{const p=$('chapterPanel');if(p.classList.contains('hidden'))openChapterPanel();else closeChapterPanel();});
$('chapterPanelClose').addEventListener('click',closeChapterPanel);
function closeRotPanel(){const p=$('rotPanel');if(p)p.classList.add('hidden');toggleRotPanel(false);}
function toggleRotPanel(on){
  const p=$('rotPanel');if(!p)return;
  const show=(on===undefined)?p.classList.contains('hidden'):on;
  if(show)p.classList.remove('hidden');else p.classList.add('hidden');
}
function applyReaderDeg(){
  const rv=$('readerView');
  const d=((readerDeg%360)+360)%360;
  readerDeg=d;
  rv.classList.remove('landscape','rot180','rot270','rotfree');
  rv.style.removeProperty('--deg');rv.style.removeProperty('--fit');
  if(d===90||d===270){rv.classList.add('landscape');if(d===270)rv.classList.add('rot270');}
  else if(d===180)rv.classList.add('rot180');
  else if(d!==0){
    rv.classList.add('rotfree');
    const w=rv.clientWidth||window.innerWidth,h=rv.clientHeight||window.innerHeight;
    const r=d*Math.PI/180;
    const W=Math.abs(w*Math.cos(r))+Math.abs(h*Math.sin(r));
    const H=Math.abs(w*Math.sin(r))+Math.abs(h*Math.cos(r));
    rv.style.setProperty('--deg',d+'deg');
    rv.style.setProperty('--fit',String(Math.min(w/W,h/H).toFixed(3)));
  }
  const lbl=$('readerRotate');if(lbl)lbl.textContent=d?('显示 '+d+'°'):'显示';
  const rg=$('rotRange');if(rg)rg.value=String(d);
  const rv2=$('rotVal');if(rv2)rv2.textContent=d+'°';
  const btns=document.querySelectorAll('#rotPresets button');
  for(let i=0;i<btns.length;i++)btns[i].classList.toggle('active',btns[i].dataset.r===String(d));
  try{localStorage.setItem('kj-rot',String(d));}catch(e){}
}
$('readerRotate').addEventListener('click',()=>toggleRotPanel());
$('rotRange').addEventListener('input',e=>{readerDeg=parseInt(e.target.value,10)||0;applyReaderDeg();});
$('zoomRange').addEventListener('input',e=>{readerZoom=parseInt(e.target.value,10)||100;applyReaderZoom();});
(function(){
  const zs=document.querySelectorAll('#zoomPresets button');
  for(let i=0;i<zs.length;i++)zs[i].addEventListener('click',()=>{
    const b=zs[i];
    if(b.dataset.z!==undefined)readerZoom=parseInt(b.dataset.z,10)||100;
    else readerZoom=Math.max(40,Math.min(150,(readerZoom||100)+(parseInt(b.dataset.d,10)||0)));
    applyReaderZoom();
  });
})();
(function(){
  const list=$('readerList');
  if(!list)return;
  list.addEventListener('wheel',e=>{
    if(!(e.ctrlKey||e.metaKey))return;
    e.preventDefault();
    readerZoom=Math.max(40,Math.min(150,readerZoom+(e.deltaY>0?-5:5)));
    applyReaderZoom();
  },{passive:false});
  let pinch0=0;
  list.addEventListener('touchmove',e=>{
    if(e.touches.length!==2)return;
    const d=Math.hypot(e.touches[0].clientX-e.touches[1].clientX,e.touches[0].clientY-e.touches[1].clientY);
    if(!pinch0){pinch0=d;return;}
    const dz=Math.round((d-pinch0)/12);
    if(dz){readerZoom=Math.max(40,Math.min(150,readerZoom+dz));pinch0=d;applyReaderZoom();}
  },{passive:true});
  list.addEventListener('touchend',()=>{pinch0=0;});
})();
/* 90/270 横屏: 手指往右 = 下一屏 (页面本身顺时针转了90度) */
(function(){
  const list=$('readerList');
  if(!list)return;
  const isLand=()=>$('readerView').classList.contains('landscape');
  const step=()=>Math.max(160,list.clientHeight*0.94);
  let sx=0,sy=0,active=false;
  list.addEventListener('touchstart',e=>{
    if(!isLand()||e.touches.length!==1){active=false;return;}
    active=true;sx=e.touches[0].clientX;sy=e.touches[0].clientY;
  },{passive:true});
  list.addEventListener('touchmove',e=>{
    if(!active||e.touches.length!==1)return;
    const dx=e.touches[0].clientX-sx;
    const dy=e.touches[0].clientY-sy;
    if(Math.abs(dx)>Math.abs(dy)&&Math.abs(dx)>8){try{e.preventDefault();}catch(err){}}
  },{passive:false});
  list.addEventListener('touchend',e=>{
    if(!active)return;
    active=false;
    const t=(e.changedTouches&&e.changedTouches[0])||null;
    if(!t)return;
    const dx=t.clientX-sx,dy=t.clientY-sy;
    if(Math.abs(dx)<45||Math.abs(dx)<Math.abs(dy))return;
    list.scrollTo({top:list.scrollTop+(dx>0?step():-step()),behavior:'smooth'});
  },{passive:true});
  list.addEventListener('wheel',e=>{
    if(!isLand()||e.ctrlKey||e.metaKey)return;
    if(Math.abs(e.deltaY)<2)return;
    e.preventDefault();
    list.scrollTo({top:list.scrollTop+(e.deltaY>0?step():-step()),behavior:'smooth'});
  },{passive:false});
})();
(function(){
  const ps=document.querySelectorAll('#rotPresets button');
  for(let i=0;i<ps.length;i++)ps[i].addEventListener('click',()=>{
    const b=ps[i];
    if(b.dataset.r!==undefined)readerDeg=parseInt(b.dataset.r,10)||0;
    else readerDeg=((readerDeg+parseInt(b.dataset.d,10))%360+360)%360;
    applyReaderDeg();
  });
})();
window.addEventListener('resize',()=>{if(readerDeg&&readerDeg%90!==0)applyReaderDeg();});
try{applyReaderDeg();}catch(e){}
try{applyReaderZoom();}catch(e){}
$('readerBack').addEventListener('click',()=>{closeRotPanel();if(readerDeg){readerDeg=0;applyReaderDeg();}closeChapterPanel();goBack(()=>showView('mainView'));});
/* ===== comic page cache (persist) + preload ===== */
const KP_CACHE='kj-comic-pages-v1';
const KP_IDX_URL='https://kuaijing.local/kj-comic-index-v1';
const KP_AHEAD=5;
const KP_MAX=60;
let kpCacheP=null,kpIdxP=null,kpIdx=null;
let kpAbort=null,kpTimer=null,kpDone=0,kpTotal=0;
function kpOpen(){
  if(!kpCacheP){
    kpCacheP=(typeof caches!=='undefined'&&caches.open)?caches.open(KP_CACHE).catch(()=>null):Promise.resolve(null);
  }
  return kpCacheP;
}
async function kpIndex(){
  if(kpIdx)return kpIdx;
  if(kpIdxP)return kpIdxP;
  kpIdxP=(async()=>{
    let list=[];
    try{
      const c=await kpOpen();
      if(c){const r=await c.match(KP_IDX_URL);if(r)list=(await r.json()).chapters||[];}
    }catch(e){}
    const m=new Map();
    for(const e of list){
      if(e&&e.c!=null&&e.id!=null&&e.urls&&e.urls.length)m.set(String(e.c)+'|'+String(e.id),e);
    }
    kpIdx=m;
    return m;
  })();
  return kpIdxP;
}
async function kpChapter(comicId,chapterId){
  if(comicId==null||chapterId==null)return null;
  const m=await kpIndex();
  return m.get(String(comicId)+'|'+String(chapterId))||null;
}
async function kpSaveIndex(){
  const c=await kpOpen();
  if(!c||!kpIdx)return;
  const arr=[...kpIdx.values()].sort((a,b)=>(b.savedAt||0)-(a.savedAt||0));
  const keep=arr.slice(0,KP_MAX),drop=arr.slice(KP_MAX);
  for(const e of drop){
    kpIdx.delete(String(e.c)+'|'+String(e.id));
    for(const u of (e.urls||[])){
      try{await c.delete(u);}catch(_){}
      try{const o=imgCache.get(u);if(o)URL.revokeObjectURL(o);imgCache.delete(u);}catch(_){}
    }
  }
  try{
    await c.put(KP_IDX_URL,new Response(JSON.stringify({v:1,ts:Date.now(),chapters:keep}),{headers:{'Content-Type':'application/json'}}));
  }catch(e){}
  return keep;
}
async function kpPutChapter(entry){
  const m=await kpIndex();
  m.set(String(entry.c)+'|'+String(entry.id),entry);
  await kpSaveIndex();
  refreshChapterMarks();
}
function kpBadge(txt){
  const el=document.getElementById('readerBadge');
  if(!el)return;
  el.textContent=txt||'';
  el.classList.toggle('on',!!txt);
}
function setImg(img,url,onDone){
  if(currentAcg){
    img.referrerPolicy='no-referrer';
    img.onload=()=>{if(onDone)onDone(true);};
    img.onerror=()=>{
      if(img.dataset.proxied){if(onDone)onDone(false);return;}
      img.dataset.proxied='1';
      img.src=RELAY_BASE+'/acg/img?u='+encodeURIComponent(url);
    };
    img.src=url;
    return;
  }
  loadXorImage(url,{store:true}).then(src=>{img.src=src;if(onDone)onDone(true);})
    .catch(()=>loadXorImage(url,{store:true,forceNet:true})
      .then(src=>{img.src=src;if(onDone)onDone(true);})
      .catch(()=>{if(onDone)onDone(false);}));
}
function kpStop(){
  if(kpTimer){clearTimeout(kpTimer);kpTimer=null;}
  if(kpAbort){try{kpAbort.abort();}catch(e){}kpAbort=null;}
  kpBadge('');
  kpDone=0;kpTotal=0;
}
function kpSchedule(){
  kpStop();
  if(!currentComic||!chaptersCache.length)return;
  if(!chaptersCache[currentChapterIdx])return;
  const cid=currentComic.id,idx=currentChapterIdx;
  kpTimer=setTimeout(()=>{kpTimer=null;kpRun(cid,idx);},1200);
}
async function kpFetchChapterImages(urls,signal){
  const ok=new Array(urls.length).fill(null);
  let i=0;
  const worker=async()=>{
    while(true){
      const k=i++;
      if(k>=urls.length)return;
      if(signal.aborted)return;
      try{await loadXorImage(urls[k],{signal:signal,store:true});ok[k]=urls[k];}
      catch(e){if(signal.aborted)return;}
    }
  };
  const ws=[];
  const n=Math.min(4,urls.length);
  for(let j=0;j<n;j++)ws.push(worker());
  await Promise.all(ws);
  return ok.filter(Boolean);
}
async function kpRun(comicId,startIdx){
  if(!currentComic||currentComic.id!==comicId)return;
  const ctrl=new AbortController();
  kpAbort=ctrl;
  const sig=ctrl.signal;
  let planned=0;
  for(let k=1;k<=KP_AHEAD;k++){
    const ch=chaptersCache[startIdx+k];
    if(!ch)break;
    const had=await kpChapter(comicId,ch.id);
    if(had&&had.urls&&had.urls.length)continue;
    planned++;
  }
  kpTotal=planned;kpDone=0;
  if(planned===0){kpBadge('');if(kpAbort===ctrl)kpAbort=null;return;}
  kpBadge('预载 0/'+planned);
  try{
    for(let k=1;k<=KP_AHEAD;k++){
      const ch=chaptersCache[startIdx+k];
      if(!ch)break;
      if(sig.aborted)return;
      if(!currentComic||currentComic.id!==comicId)return;
      const have=await kpChapter(comicId,ch.id);
      if(have&&have.urls&&have.urls.length)continue;
      let pages=null;
      try{
        pages=await getChapterPages({id:ch.id,name:ch.name,pay:ch.pay||0},{noEnumerate:true,comicId:comicId,signal:sig});
      }catch(e){
        if(sig.aborted)return;
        continue;
      }
      if(sig.aborted)return;
      if(!pages||pages.length<2)continue;
      const ok=await kpFetchChapterImages(pages,sig);
      if(sig.aborted)return;
      if(!ok.length)continue;
      await kpPutChapter({c:comicId,id:ch.id,name:ch.name,pay:ch.pay||0,urls:ok,savedAt:Date.now()});
      kpDone++;
      kpBadge('预载 '+kpDone+'/'+planned);
    }
    if(!sig.aborted)kpBadge(kpDone>0?('已缓存 '+kpDone):'');
  }finally{
    if(kpAbort===ctrl){
      kpAbort=null;
      if(kpDone>0&&!sig.aborted)setTimeout(()=>{if(!kpAbort)kpBadge('');},3000);
    }
  }
}
function kpWarmIndex(){(async()=>{try{await kpIndex();}catch(e){}})();}
document.addEventListener('visibilitychange',()=>{
  const rv=document.getElementById('readerView');
  if(document.hidden){kpStop();}
  else if(rv&&!rv.classList.contains('hidden')){kpSchedule();}
});
kpWarmIndex();

/* ===== novel ===== */
function novelBlocked(name){return nameBlocked(name)||hotBad(name);}
function formatTextNum(n){n=parseInt(n)||0;if(n>=10000)return (n/10000).toFixed(1)+'万';return String(n);}
function renderNovelCard(b){
  const div=document.createElement('a');
  div.className='card';
  div.href=mkHref('n',b.id,b.name,3);
  const coverUrl=resolveImgUrl(b.pic);
  div.innerHTML='<div class="cover"><span>\uD83D\uDCDA</span>'+(b.pay!==0?'<span class="badge">VIP</span>':'')+'</div>'+
    '<div class="info"><div class="name">'+esc(b.name)+'</div><div class="sub">'+esc(b.author||'无名')+' · '+formatTextNum(b.text_num)+'字</div></div>';
  div.addEventListener('click',e=>{
    if(e.metaKey||e.ctrlKey||e.shiftKey||e.altKey||e.button!==0)return;
    e.preventDefault();
    navTo(div.getAttribute('href'),()=>openNovel(b));
  });
  grid.appendChild(div);
  if(coverUrl)lazyImg(div.querySelector('.cover'),coverUrl);
}
async function openNovel(book){
  currentNovel=book;
  recordHistory('novel',book);
  novelBookName=book.name||'';
  novelTitle.textContent=book.name;
  novelBody.innerHTML='<div class="loadingHint">加载章节...</div>';
  showView('novelView');
  try{
    await ensureLogin();
    const r=await apiCall('/v2/api/book/chapter',{bid:book.id,id:''});
    const d=r.data||{};
    novelChapters=(d.chapter||[]).map(c=>({id:c.id,name:c.name,pay:c.pay||0,bullion:c.bullion||0}));
    renderNovelChapterButtons();
    if(novelChapters.length>0)loadNovelChapter(0);
    else novelBody.innerHTML='<div class="loadingHint">无章节</div>';
  }catch(e){
    novelBody.innerHTML='<div class="loadingHint">加载失败: '+esc(e.message)+'</div>';
  }
}
function renderNovelChapterButtons(){
  const list=$('novelChapterList');
  list.innerHTML='';
  for(let i=0;i<novelChapters.length;i++){
    const ch=novelChapters[i];
    const btn=document.createElement('button');
    btn.className='chapterItem';
    btn.textContent=ch.name+(ch.pay!==0?' \u{1F512}':'');
    btn.addEventListener('click',()=>{closeNovelChapterPanel();loadNovelChapter(i);});
    list.appendChild(btn);
  }
}
async function loadNovelChapter(idx){
  if(idx<0||idx>=novelChapters.length)return;
  novelChapterIdx=idx;
  const ch=novelChapters[idx];
  novelBody.innerHTML='<div class="loadingHint">加载正文...</div>';
  try{
    await ensureLogin();
    let cr=await apiCall('/v2/api/book/chapter',{bid:currentNovel.id,id:ch.id});
    let d=cr.data||{};
    let data=d.data||{};
    if(data&&!data.auth&&ch.pay!==0){
      const br=await apiCall('/v2/api/book/buy',{id:ch.id});
      if(br&&br.data){data=br.data.data||br.data||data;if(data.path)data.auth=true;}
    }
    const path=(data&&data.path)||'';
    if(!path){novelBody.innerHTML='<div class="loadingHint">该章节无内容</div>';return;}
    const txt=await fetchText(path);
    const paras=parseNovelText(txt);
    if(!paras.length){novelBody.innerHTML='<div class="loadingHint">正文解析失败</div>';return;}
    renderNovelBody(ch,paras);
  }catch(e){
    novelBody.innerHTML='<div class="loadingHint">加载失败: '+esc(e.message)+'</div>';
  }
}
async function fetchText(url){
  const resp=await fetch(url);
  if(!resp.ok)throw new Error('HTTP '+resp.status);
  return await resp.text();
}
function parseNovelText(html){
  const decode=t=>t.replace(/<[^>]*>/g,'').replace(/&nbsp;/g,' ').replace(/&ldquo;/g,'\u201C').replace(/&rdquo;/g,'\u201D').replace(/&hellip;/g,'\u2026').replace(/&amp;/g,'&').replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&quot;/g,'"').trim();
  const out=[];
  let m,re;
  re=/<div[^>]*class=['"]transcode-is-sb['"][^>]*>([\s\S]*?)<\/div>/g;
  while((m=re.exec(html))!==null){const t=decode(m[1]);if(t)out.push(t);}
  if(out.length)return out;
  re=/<p[^>]*>([\s\S]*?)<\/p>/g;
  while((m=re.exec(html))!==null){const t=decode(m[1]);if(t)out.push(t);}
  if(out.length)return out;
  const plain=html.replace(/<br[^>]*>/gi,'\n').replace(/<[^>]*>/g,'');
  const lines=plain.split(/\n+/).map(decode).filter(t=>t);
  if(lines.length)return lines;
  const single=decode(html);
  return single?[single]:[];
}
function renderNovelBody(ch,paras){
  const wrap=document.createElement('div');
  const title=document.createElement('div');title.className='novelChapterTitle';title.textContent=ch.name;
  const book=document.createElement('div');book.className='novelBookTitle';book.textContent=novelBookName;
  wrap.appendChild(title);wrap.appendChild(book);
  wrap.appendChild(novelNavBar());
  for(const p of paras){
    const pe=document.createElement('p');pe.textContent=p;wrap.appendChild(pe);
  }
  wrap.appendChild(novelNavBar());
  novelBody.innerHTML='';
  novelBody.appendChild(wrap);
  novelTitle.textContent=ch.name;
  novelBody.scrollTop=0;
}
function novelNavBar(){
  const nav=document.createElement('div');nav.className='novelNav';
  const prev=document.createElement('button');prev.textContent='上一章';prev.disabled=novelChapterIdx<=0;
  prev.addEventListener('click',()=>{if(novelChapterIdx>0)loadNovelChapter(novelChapterIdx-1);});
  const next=document.createElement('button');next.textContent='下一章';next.disabled=novelChapterIdx>=novelChapters.length-1;
  next.addEventListener('click',()=>{if(novelChapterIdx<novelChapters.length-1)loadNovelChapter(novelChapterIdx+1);});
  nav.appendChild(prev);nav.appendChild(next);
  return nav;
}
function closeNovelChapterPanel(){$('novelChapterPanel').classList.add('hidden');}
function openNovelChapterPanel(){$('novelChapterPanel').classList.remove('hidden');}
$('novelBack').addEventListener('click',()=>{closeNovelChapterPanel();goBack(()=>showView('mainView'));});
$('novelCatalog').addEventListener('click',()=>{const p=$('novelChapterPanel');if(p.classList.contains('hidden'))openNovelChapterPanel();else closeNovelChapterPanel();});
$('novelChapterPanelClose').addEventListener('click',closeNovelChapterPanel);

/* ===== video player ===== */
let hlsLoaded=false;
async function ensureHls(){
  if(hlsLoaded)return;
  return new Promise((resolve,reject)=>{
    const s=document.createElement('script');
    s.src='https://cdn.jsdelivr.net/npm/hls.js@1.5.13/dist/hls.min.js';
    s.onload=()=>{hlsLoaded=true;resolve();};
    s.onerror=()=>reject(new Error('hls.js 加载失败'));
    document.head.appendChild(s);
  });
}
async function openVod(v){
  currentAcg=null;
  playerReturn='mainView';
  recordHistory('vod',v);
  playerTitle.textContent=v.vod_name;
  playerStatus.textContent='获取播放地址...';
  videoEl.src='';
  showView('playerView');
  try{
    await ensureLogin();
    let key='sex8';
    try{
      const det=await apiCall('/v2/api/app/vodDetails',{id:v.vod_id});
      const dd=det.data||{};
      const pu=dd.vod_play_url||[];
      if(pu.length>0&&pu[0].key)key=pu[0].key;
    }catch(e){}
    const r=await apiCall('/v2/api/app/advUnlockVod',{id:v.vod_id,type:'play',key,index:0,user_uuid:''});
    const m3u8=((r.data||{}).vod_play_url||{}).h264||'';
    if(!m3u8)throw new Error('获取播放地址失败');
    playerStatus.textContent='';
    const isApple=/iPad|iPhone|iPod/.test(navigator.userAgent)||(navigator.userAgent.indexOf('Mac')>=0&&navigator.maxTouchPoints>1);
    // Chrome/Edge 对 apple.mpegurl 会返回 "maybe" 但实际放不了 HLS, 只信 Safari/iOS
    const canNative=isApple;
    if(canNative){
      videoEl.src=m3u8;
      videoEl.play().catch(()=>{});
    }else{
      await ensureHls();
      if(window.Hls&&window.Hls.isSupported()){
        if(videoEl._hls)videoEl._hls.destroy();
        const hls=new window.Hls({
          startLevel:-1,
          maxBufferLength:120,
          maxMaxBufferLength:300,
          maxBufferSize:256*1024*1024,
          manifestLoadingTimeOut:20000,
          fragLoadingTimeOut:60000,
          fragLoadingMaxRetry:8,
          fragLoadingRetryDelay:300,
          enableWorker:true,
          abrEwmaDefaultEstimate:1200000
        });
        hls.loadSource(m3u8);
        hls.attachMedia(videoEl);
        hls.on(window.Hls.Events.MANIFEST_PARSED,()=>{videoEl.play().catch(()=>{});});
        hls.on(window.Hls.Events.ERROR,(ev,data)=>{
          if(data.fatal){playerStatus.textContent='播放错误: '+data.details;hls.destroy();}
        });
        videoEl._hls=hls;
      }else playerStatus.textContent='浏览器不支持 HLS 播放';
    }
  }catch(e){playerStatus.textContent='播放失败: '+e.message;}
}
$('playerBack').addEventListener('click',()=>{
  $('playerEpPanel').classList.add('hidden');
  plSetNavVisible(false);
  if(videoEl._hls){videoEl._hls.destroy();videoEl._hls=null;}
  videoEl.pause();videoEl.src='';
  if(playerReturn==='externalView'){
    extListMode=true;
    goBack(()=>{renderExternal();showView('externalView');});
  }else if(playerReturn==='acgReader'){
    goBack(()=>showView('readerView'));
  }else{
    goBack(()=>showView('mainView'));
  }
});
/* ===== forum detail ===== */
async function openForum(f){
  currentAcg=null;
  forumTitle.textContent=f.title;
  forumBody.innerHTML='<div style="text-align:center;padding:40px;color:var(--text2)">加载中...</div>';
  showView('forumView');
  try{
    const r=await apiCall('/v2/api/forum/postsDetails',{id:f.id});
    const d=r.data||{};
    forumBody.innerHTML='';
    const meta=document.createElement('div');
    meta.className='forumMeta';
    const author=d.user?(d.user.user_nick_name||d.user.user_name):'';
    meta.textContent=(author?author+' · ':'')+(d.hits||0)+'阅 · '+(d.liked||0)+'赞';
    forumBody.appendChild(meta);
    const content=document.createElement('div');
    content.className='forumContent';
    content.textContent=d.content||f.title;
    forumBody.appendChild(content);
    const pics=d.pic||[];
    for(const url of pics){
      if(!url)continue;
      const img=document.createElement('img');
      img.className='forumImg';img.alt='';
      forumBody.appendChild(img);
      loadXorImage(url).then(src=>{img.src=src;}).catch(()=>{img.remove();});
    }
    const plays=d.play_url||[];
    for(const p of plays){
      const h=p.h264||'';
      if(!h)continue;
      const v=document.createElement('video');
      v.controls=true;v.playsInline=true;
      v.style.cssText='width:100%;border-radius:6px;margin-bottom:8px;';
      v.src=h;v.preload='metadata';
      forumBody.appendChild(v);
    }
  }catch(e){
    forumBody.innerHTML='<div style="text-align:center;padding:40px;color:var(--text2)">加载失败: '+esc(e.message)+'</div>';
  }
}
$('forumBack').addEventListener('click',()=>goBack(()=>showView('mainView')));
/* ===== view scroll memory ===== */
function currentViewId(){
  for(const v of KJ_VIEWS){const el=$(v);if(el&&!el.classList.contains('hidden'))return v;}
  return 'mainView';
}
function saveScroll(id){
  if(id==='mainView'){
    const se=document.scrollingElement||document.documentElement;
    VIEW_SCROLL.mainView=se?(se.scrollTop||0):0;
  }else if(id==='externalView'){
    if(!extListMode)return;
    const b=$('extBody');if(b)VIEW_SCROLL.externalView=b.scrollTop||0;
  }
}
function applyScroll(id){
  if(id==='mainView'){
    const y=VIEW_SCROLL.mainView||0;
    const se=document.scrollingElement||document.documentElement;
    if(se)se.scrollTop=y;
    window.scrollTo(0,y);
  }else if(id==='externalView'){
    const b=$('extBody');if(b)b.scrollTop=VIEW_SCROLL.externalView||0;
  }
}
function restoreScrollSoon(id){
  if(id!=='mainView'&&id!=='externalView')return;
  scrollGuardUntil=Date.now()+1200;
  applyScroll(id);
  requestAnimationFrame(()=>applyScroll(id));
  setTimeout(()=>applyScroll(id),90);
  setTimeout(()=>applyScroll(id),280);
}
function resetMainScroll(){
  VIEW_SCROLL.mainView=0;
  const se=document.scrollingElement||document.documentElement;
  if(se)se.scrollTop=0;
  window.scrollTo(0,0);
}
function resetExtScroll(){
  VIEW_SCROLL.externalView=0;
  const b=$('extBody');if(b)b.scrollTop=0;
}
/* ===== view switching ===== */
function showView(id){
  const prev=currentViewId();
  if(prev!==id)saveScroll(prev);
  if(id!=='readerView'){doSaveReaderPos(true);saveAcgPos(true);tgSavePos(true);}
  KJ_VIEWS.forEach(v=>{
    $(v).classList.toggle('hidden',v!==id);
  });
  if(id!=='readerView')kpStop();
  restoreScrollSoon(id);
}
/* ===== reading position ===== */
const POS_KEY='kj_pos_v1';
function getPosMap(){try{return JSON.parse(localStorage.getItem(POS_KEY)||'{}');}catch(e){return {};}}
function posOf(mid){if(mid==null)return null;return getPosMap()[String(mid)]||null;}
function setPos(mid,obj){try{const m=getPosMap();m[String(mid)]=obj;localStorage.setItem(POS_KEY,JSON.stringify(m));}catch(e){}}
function saveReaderPos(){
  if(posTimer)return;
  posTimer=setTimeout(()=>{posTimer=0;doSaveReaderPos(false);},700);
}
function doSaveReaderPos(force){
  if(!currentComic||!loadedChapters.length||!readerList)return;
  if(readerList.classList.contains('hidden'))return;
  const rect=readerList.getBoundingClientRect();
  if(rect.width===0||rect.height===0)return;
  let cur=loadedChapters[0];
  for(const c of loadedChapters){if(c.element.getBoundingClientRect().top-rect.top<=120)cur=c;}
  const imgs=cur.element.querySelectorAll('img');
  let painted=0;
  for(let i=0;i<imgs.length;i++){if(imgs[i].naturalWidth>0)painted++;}
  if(!force&&painted<(cur.total||imgs.length)&&(cur.tries||0)<3){
    cur.tries=(cur.tries||0)+1;
    setTimeout(()=>{cur.tries=0;doSaveReaderPos(false);},900);
    return;
  }
  let page=0;
  for(let i=0;i<imgs.length;i++){if(imgs[i].getBoundingClientRect().top-rect.top<=120)page=i;else break;}
  setPos(currentComic.id,{cid:cur.id,name:cur.name,page:page,ts:Date.now()});
}
function saveAcgPos(force){
  if(!currentAcg||!readerList)return;
  if(readerList.classList.contains('hidden'))return;
  const rect=readerList.getBoundingClientRect();
  if(rect.width===0||rect.height===0)return;
  const run=()=>{
    acgPosTimer=0;
    if(!currentAcg)return;
    const imgs=readerList.querySelectorAll('img');
    let page=0;
    for(let i=0;i<imgs.length;i++){if(imgs[i].getBoundingClientRect().top-rect.top<=120)page=i;else break;}
    setPos('a'+currentAcg.id,{page:page,title:currentAcg.title,ts:Date.now()});
  };
  if(force){if(acgPosTimer){clearTimeout(acgPosTimer);acgPosTimer=0;}run();return;}
  if(acgPosTimer)return;
  acgPosTimer=setTimeout(run,600);
}
function restoreScrollTo(container,page){
  restoringPos=true;restoreTries=0;let stable=0,last=-1;
  const tick=()=>{
    const imgs=container.querySelectorAll('img');
    const target=imgs[Math.min(page,imgs.length-1)];
    if(target){
      const rl=readerList.getBoundingClientRect();
      const off=target.getBoundingClientRect().top-rl.top+readerList.scrollTop-6;
      const want=Math.max(0,off);
      if(Math.abs(want-readerList.scrollTop)>4) readerList.scrollTop=want;
      stable=(Math.abs(off-last)<3)?stable+1:0;
      last=off;
    }
    restoreTries++;
    if(restoreTries<24&&stable<2) setTimeout(tick,350); else {restoringPos=false;saveReaderPos();}
  };
  tick();
}
/* ===== history ===== */
const HIST_KEY='kj_history_v1';
function getHistory(){try{return JSON.parse(localStorage.getItem(HIST_KEY)||'[]');}catch(e){return [];}}
function saveHistory(list){try{localStorage.setItem(HIST_KEY,JSON.stringify(list));}catch(e){}}
function recordHistory(type,item){
  if(!item)return;
  const id=item.id||item.vod_id;
  if(!id)return;
  let list=getHistory();
  list=list.filter(e=>!(e.type===type&&e.id===id));
  let rec={type,id,ts:Date.now()};
  if(type==='acg')rec.item={id:item.id,title:item.title,cover:item.cover,cat:item.cat,seg:item.seg,kind:item.type};
  else if(type==='comic')rec.item={id:item.id,name:item.name,pic:item.pic,pay:item.pay,latest_chapter_name:item.latest_chapter_name};
  else if(type==='vod')rec.item={vod_id:item.vod_id,vod_name:item.vod_name,vod_pic:item.vod_pic,vod_duration:item.vod_duration,vod_mode:item.vod_mode,type_id:item.type_id};
  else rec.item={id:item.id,name:item.name,pic:item.pic,author:item.author,text_num:item.text_num,pay:item.pay,latest_chapter_name:item.latest_chapter_name};
  list.unshift(rec);
  if(list.length>100)list=list.slice(0,100);
  saveHistory(list);
}
function renderHistory(){
  grid.innerHTML='';
  const list=getHistory();
  if(list.length===0){
    grid.innerHTML='<div style="grid-column:1/-1;text-align:center;color:var(--text2);padding:48px 0;">暂无观看记录</div>';
    return;
  }
  const clear=document.createElement('button');
  clear.className='chip';
  clear.style.cssText='grid-column:1/-1;justify-self:start;color:var(--text2);';
  clear.textContent='清空历史';
  clear.addEventListener('click',()=>{saveHistory([]);renderHistory();});
  grid.appendChild(clear);
  const labels={comic:'漫画',vod:'视频',novel:'小说',acg:'外站'};
  for(const e of list){
    const it=e.item||{};
    const name=e.type==='vod'?it.vod_name:(e.type==='acg'?it.title:it.name);
    const pic=e.type==='vod'?it.vod_pic:(e.type==='acg'?it.cover:it.pic);
    let sub=e.type==='vod'?(it.vod_duration?('时长 '+it.vod_duration):''):(it.latest_chapter_name?('更新至 '+it.latest_chapter_name):'');
    if(e.type==='acg')sub=esc((it.cat||'')+(it.seg?' · '+it.seg:''));
    if(e.type==='comic'){const p=posOf(it.id);if(p&&p.name)sub='读到 '+p.name+(it.latest_chapter_name?' · 更新至 '+it.latest_chapter_name:'');}
    const div=document.createElement('a');
    div.className='card';
    div.href=e.type==='comic'?mkHref('c',it.id,it.name,4):e.type==='vod'?mkHref('v',it.vod_id,it.vod_name,4):e.type==='acg'?(mkHref('a',it.id,it.title,4)+'&s='+encodeURIComponent(it.seg||'h')):mkHref('n',it.id,it.name,4);
    const coverUrl=e.type==='acg'?(it.cover?(RELAY_BASE+'/acg/img?u='+encodeURIComponent(it.cover)):null):resolveImgUrl(pic);
    div.innerHTML='<div class="cover"><span>'+labels[e.type]+'</span></div>'+
      '<div class="info"><div class="name">'+esc(name||'')+'</div><div class="sub">'+esc(sub)+'</div></div>';
    div.addEventListener('click',ev=>{
      if(ev.metaKey||ev.ctrlKey||ev.shiftKey||ev.altKey||ev.button!==0)return;
      ev.preventDefault();
      navTo(div.getAttribute('href'),()=>{
        if(e.type==='acg')openAcgComic({id:it.id,title:it.title,cover:it.cover,cat:it.cat,seg:it.seg||'h',type:it.kind});
        else if(e.type==='comic')openComic(it);
        else if(e.type==='vod')openVod(it);
        else openNovel(it);
      });
    });
    grid.appendChild(div);
    if(coverUrl)lazyImg(div.querySelector('.cover'),coverUrl);
  }
}

/* ===== external resources (91porna + 黄桃短剧) via relay ===== */
function openExternal(){
  showView('externalView');
  if(extLoaded){renderExternal();return;}
  loadExternal();
}
function extStatusShow(msg,retry){
  const st=$('extStatus');
  st.classList.remove('hidden');
  $('extBody').classList.add('hidden');
  st.innerHTML='<div class="extStatusTxt">'+esc(msg)+'</div>'+(retry?'<button class="chip" id="extRetry">检查网络</button>':'');
  if(retry)$('extRetry').addEventListener('click',loadExternal);
}
function extStatusHide(){
  $('extStatus').classList.add('hidden');
  $('extBody').classList.remove('hidden');
}
let _extReq=null;
async function loadExternal(){
  if(_extReq){try{_extReq.abort();}catch(e){}}
  const ac=(typeof AbortController!=='undefined')?new AbortController():null;
  _extReq=ac;
  extStatusShow('正在检查网络(需翻墙)...', true);
  $('extBody').innerHTML='';
  const timer=setTimeout(function(){try{ac&&ac.abort();}catch(e){}}, 9000);
  try{
    const resp=await fetch(RELAY_BASE+'/list', ac?{signal:ac.signal,cache:'no-store'}:{cache:'no-store'});
    if(_extReq!==ac)return;
    if(!resp.ok)throw new Error('HTTP '+resp.status);
    const d=await resp.json();
    if(_extReq!==ac)return;
    if(d.error)throw new Error(d.error);
    extData={dramas:d.dramas||[],videos:d.videos||[],novels:d.novels||[]};
    extLoaded=true;
    extStatusHide();
    renderExternal();
  }catch(e){
    if(_extReq!==ac)return;
    extLoaded=false;extData=null;
    extStatusShow('未检测到翻墙网络。请先开 VPN/代理，然后点「检查网络」。', true);
  }finally{
    clearTimeout(timer);
    if(_extReq===ac)_extReq=null;
  }
}
function emptyHint(msg){return '<div class="loadingHint" style="grid-column:1/-1">'+esc(msg)+'</div>';}
const IMG_KEY='f5d965df75336270', IMG_IV='97b60394abc2fbe1';
let _imgKeyPromise=null;
function _imgKey(){ if(!_imgKeyPromise){ _imgKeyPromise=crypto.subtle.importKey('raw',new TextEncoder().encode(IMG_KEY),{name:'AES-CBC'},false,['decrypt']); } return _imgKeyPromise; }
function _isImg(buf){
  const d=new Uint8Array(buf);
  return (d[0]===0xFF&&d[1]===0xD8)||(d[0]===0x89&&d[1]===0x50)||(d[0]===0x47&&d[1]===0x49&&d[2]===0x46)||(d[0]===0x52&&d[1]===0x49&&d[2]===0x46&&d[3]===0x46)||(d[0]===0x42&&d[1]===0x4D);
}
function _imgMime(buf){
  const d=new Uint8Array(buf);
  if(d[0]===0x89)return 'image/png';
  if(d[0]===0x47)return 'image/gif';
  if(d[0]===0x52&&d[1]===0x49)return 'image/webp';
  return 'image/jpeg';
}
async function loadEncImg(container,url){
  try{
    const r=await fetch(url);
    if(!r.ok)return;
    let buf=await r.arrayBuffer();
    if(!_isImg(buf)){
      const key=await _imgKey();
      buf=await crypto.subtle.decrypt({name:'AES-CBC',iv:new TextEncoder().encode(IMG_IV)},key,buf);
    }
    const blob=new Blob([buf],{type:_imgMime(buf)});
    const img=document.createElement('img');
    img.loading='lazy';img.src=URL.createObjectURL(blob);img.alt='';
    img.onload=()=>{const sp=container.querySelector('span');if(sp)sp.style.display='none';};
    img.onerror=()=>{img.remove();};
    container.insertBefore(img,container.firstChild);
  }catch(e){}
}
function normCover(u){
  if(!u)return u;
  // 旧图床域已死, 同一路径改写为现行 drleao 图床 (无需 auth_key 也能取到密文)
  return u.replace(/expose\.eisees\.com/gi,'pic.drleao.cn');
}
function extCover(container,url){
  if(!url)return;
  url=normCover(url);
  if(/drleao\.cn/i.test(url)){ loadEncImg(container,url); return; }
  const img=document.createElement('img');
  img.loading='lazy';img.src=url;img.alt='';
  img.onload=()=>{const sp=container.querySelector('span');if(sp)sp.style.display='none';};
  img.onerror=()=>{img.remove();};
  container.insertBefore(img,container.firstChild);
}
let extCat=null;
let extCatsData=null;
let extCatsTried=false;
let extRemote=null;
let extSeq=0;
let extKwRemote=null;
let EXT_INDEX=null;
let EXT_INDEX_P=null;
const EXT_LOCAL_PAGE=20;
function loadExtIndex(){
  if(EXT_INDEX)return Promise.resolve(EXT_INDEX);
  if(EXT_INDEX_P)return EXT_INDEX_P;
  EXT_INDEX_P=fetch('index/v91_index.json',{cache:'no-cache'}).then(r=>r.json()).then(d=>{
    EXT_INDEX=(d&&d.cats)?d.cats:{};
    return EXT_INDEX;
  }).catch(()=>{EXT_INDEX=null;EXT_INDEX_P=null;return null;});
  return EXT_INDEX_P;
}
function extTheme(){
  if(tgMode)return 'tg';
  return extSection===0?'drama':extSection===1?'video':'novel';
}
const EXT_CONTENT_CATS=['吃瓜爆料','熟女做爱','成人动漫','童颜巨乳','少妇换妻','内射中出','会所按摩','91探花','丝袜美腿','极品少妇','三级片','无码专区','国产自拍','制服诱惑','偷拍偷录'];
function extIsContentCat(label){
  if(!label)return false;
  if(extCatsData&&extCatsData.some(c=>c.label===label))return true;
  return EXT_CONTENT_CATS.indexOf(label)>=0;
}
function loadExtCats(){
  if(extCatsTried)return;
  extCatsTried=true;
  fetch(RELAY_BASE+'/cats',{cache:'no-store'}).then(r=>r.json()).then(d=>{
    extCatsData=(d&&d.cats&&d.cats.length)?d.cats:EXT_CONTENT_CATS.map(l=>({label:l}));
    if(extSection===1&&!extCat&&!extKwRemote)renderExtCats();
  }).catch(()=>{extCatsData=EXT_CONTENT_CATS.map(l=>({label:l}));extCatsTried=false;});
}
function extPickCat(c){
  extCat=c;
  extRemote=null;
  extKwRemote=null;
  extSeq++;
  if(tgMode){
    tgCat=(c==null?'0':String(c));
    tgState={items:[],page:0,more:true,busy:false,failed:'',kw:''};
    tgSeq++;
  }
  extKw='';
  const inp=$('extSearchInput');
  if(inp)inp.value='';
  extListMode=true;resetExtScroll();
  renderExternal();
}
function extSortCats(){
  const out=[];
  if(extData&&extSection===1){
    const seen={};
    for(const v of extData.videos){if(v.cat&&!seen[v.cat]){seen[v.cat]=1;out.push(v.cat);}}
  }
  return out;
}
function renderExtCats(){
  const row=$('extCatRow');
  row.innerHTML='';
  const mk=(txt,val,on)=>{
    const b=document.createElement('span');
    b.className='extChip'+(on?' active':'');
    b.textContent=txt;
    b.addEventListener('click',()=>extPickCat(val));
    row.appendChild(b);
  };
  if(tgMode){
    const cats=tgCats[tgTab]||[];
    mk('全部','0',tgCat==='0');
    for(const c of cats)mk(c.label,c.id,String(c.id)===String(tgCat));
    return;
  }
  const add=(txt,val)=>mk(txt,val,extCat===val);
  const labels=[];
  if(extSection===1){
    loadExtCats();
    const csrc=(extCatsData&&extCatsData.length)?extCatsData:EXT_CONTENT_CATS.map(l=>({label:l}));
    for(const c of csrc)labels.push(c.label);
    for(const c of extSortCats()){if(labels.indexOf(c)<0)labels.push(c);}
  }else if(extData){
    const list=extSection===0?extData.dramas:extData.novels;
    const seen={};
    for(const it of list){if(it.cat&&!seen[it.cat]){seen[it.cat]=1;labels.push(it.cat);}}
  }
  add('全部',null);
  for(const c of labels)add(c,c);
}
function renderExtHot(){
  const row=$('extHotRow');
  if(tgMode){
    const hot=(tgHomeCache&&tgHomeCache.hot)||[];
    if(!hot.length){row.classList.add('hidden');return;}
    row.classList.remove('hidden');
    const lb=document.createElement('span');
    lb.className='extHotLabel';lb.textContent='热搜';
    row.appendChild(lb);
    for(const h of hot.slice(0,10)){
      const b=document.createElement('span');
      b.className='extChip hot';b.textContent=h.kw;
      b.addEventListener('click',()=>{
        const inp=$('extSearchInput');
        if(inp)inp.value=h.kw;
        tgState={items:[],page:0,more:true,busy:false,failed:'',kw:h.kw};
        tgSeq++;tgLoad(1);
      });
      row.appendChild(b);
    }
    return;
  }
  row.innerHTML='';
  if(extSection!==1||!extData){row.classList.add('hidden');return;}
  const cnt={};
  for(const v of extData.videos){if(v.cat)cnt[v.cat]=(cnt[v.cat]||0)+1;}
  if(extCatsData){for(const c of extCatsData){if(cnt[c.label]===undefined)cnt[c.label]=1;}}
  const hot=Object.keys(cnt).sort((a,b)=>cnt[b]-cnt[a]).slice(0,9);
  if(!hot.length){row.classList.add('hidden');return;}
  row.classList.remove('hidden');
  const lb=document.createElement('span');
  lb.className='extHotLabel';lb.textContent='\u70ed\u95e8';
  row.appendChild(lb);
  for(const h of hot){
    const b=document.createElement('span');
    b.className='extChip hot'+(extCat===h?' active':'');
    b.textContent=h;
    b.addEventListener('click',()=>extPickCat(h));
    row.appendChild(b);
  }
}
function renderExtMoreTail(){
  const old=document.getElementById('extMoreTail');
  if(old)old.remove();
  const d=document.createElement('div');
  d.id='extMoreTail';d.className='extMoreTail';d.textContent='\u4e0b\u6ed1\u52a0\u8f7d\u66f4\u591a';
  d.addEventListener('click',()=>{if(tgMode){if(tgState&&!tgState.busy)tgLoad(tgState.page+1);return;}if(extRemote&&!extRemote.busy)extRemoteNext(extSeq);});
  $('extBody').appendChild(d);
}
function renderExtEndTail(){
  const old=document.getElementById('extMoreTail');
  if(old)old.remove();
  if(document.getElementById('extMoreEnd'))return;
  const d=document.createElement('div');
  d.id='extMoreEnd';d.className='extMoreEnd';d.textContent='\u6ca1\u6709\u66f4\u591a\u4e86';
  $('extBody').appendChild(d);
}
function extEmptyRetry(msg,onTap){
  const d=document.createElement('div');
  d.className='loadingHint';
  d.style.gridColumn='1/-1';
  d.style.cursor='pointer';
  d.textContent=msg;
  d.addEventListener('click',onTap);
  return d;
}
function renderExtRemoteBody(){extListMode=true;renderExtRemoteBodyInner();restoreScrollSoon('externalView');}
function renderExtRemoteBodyInner(){
  const st=extRemote;
  if(!st)return;
  const body=$('extBody');
  body.innerHTML='';
  if(!st.videos.length){
    if(st.busy){body.innerHTML=emptyHint('\u6b63\u5728\u68c0\u7d22\u300c'+st.key+'\u300d...');return;}
    const msg=st.failed?('\u52a0\u8f7d\u5931\u8d25\uff1a'+st.failed+' \u00b7 \u70b9\u6b64\u91cd\u8bd5'):('\u300c'+st.key+'\u300d\u6682\u65e0\u89c6\u9891 \u00b7 \u70b9\u6b64\u91cd\u8bd5');
    body.appendChild(extEmptyRetry(msg,()=>{if(st.busy)return;extRemoteStart(st.mode,st.key);}));
    return;
  }
  for(const v of st.videos)renderExtVideoCard(v);
  if(st.more)renderExtMoreTail();
  else renderExtEndTail();
}
async function extLocalStart(cat){
  extListMode=true;
  const seq=++extSeq;
  $('extStatus').classList.add('hidden');
  $('extBody').classList.remove('hidden');
  $('extBody').innerHTML=emptyHint('\u6b63\u5728\u52a0\u8f7d\u300c'+cat+'\u300d...');
  const cats=await loadExtIndex();
  if(seq!==extSeq)return;
  const items=(cats&&cats[cat])||[];
  if(!items.length){extRemoteStart('cat',cat);return;}
  extRemote={mode:'cat',key:cat,local:true,all:items,page:1,videos:items.slice(0,EXT_LOCAL_PAGE),more:items.length>EXT_LOCAL_PAGE,busy:false,failed:''};
  renderExtRemoteBody();
}
async function extRemoteStart(mode,key){
  extListMode=true;
  const seq=++extSeq;
  const st={mode:mode,key:key,page:0,videos:[],more:true,busy:false,failed:''};
  extRemote=st;
  $('extStatus').classList.add('hidden');
  $('extBody').classList.remove('hidden');
  $('extBody').innerHTML=emptyHint('\u6b63\u5728\u68c0\u7d22\u300c'+key+'\u300d...');
  await extRemoteNext(seq);
}
async function extRemoteNext(seq){
  const st=extRemote;
  if(seq!==extSeq||!st||st.busy)return;
  if(st.local){
    st.busy=true;
    const from=st.page*EXT_LOCAL_PAGE;
    const got=st.all.slice(from,from+EXT_LOCAL_PAGE);
    st.videos=st.videos.concat(got);
    st.page++;
    st.more=st.page*EXT_LOCAL_PAGE<st.all.length;
    st.busy=false;
    const tail=document.getElementById('extMoreTail');
    if(tail)tail.remove();
    for(const v of got)renderExtVideoCard(v);
    if(st.more)renderExtMoreTail();else renderExtEndTail();
    return;
  }
  st.busy=true;
  const qs=st.mode==='cat'?'cat='+encodeURIComponent(st.key):'kw='+encodeURIComponent(st.key);
  let ac=null;
  try{
    if(typeof AbortController!=='undefined')ac=new AbortController();
    const timer=setTimeout(()=>{try{ac&&ac.abort();}catch(e){}},18000);
    let resp;
    try{
      resp=await fetch(RELAY_BASE+'/v91search?'+qs+'&page='+(st.page+1),ac?{signal:ac.signal,cache:'no-store'}:{cache:'no-store'});
    }finally{clearTimeout(timer);}
    if(seq!==extSeq)return;
    if(!resp.ok)throw new Error('HTTP '+resp.status);
    const d=await resp.json();
    if(seq!==extSeq)return;
    if(d&&d.error)throw new Error(d.error);
    const have={};
    for(const v of st.videos)have[v.key]=1;
    const got=[];
    for(const v of (d.videos||[])){if(!have[v.key]){have[v.key]=1;got.push(v);}}
    st.page++;
    st.videos=st.videos.concat(got);
    st.more=got.length>0&&st.page<(d.pages||99);
    if(st.page===1)renderExtRemoteBody();
    else{
      const tail=document.getElementById('extMoreTail');
      if(tail)tail.remove();
      for(const v of got)renderExtVideoCard(v);
      if(st.more)renderExtMoreTail();
      else renderExtEndTail();
    }
  }catch(e){
    if(seq!==extSeq)return;
    if(st.page===0){
      st.failed=String(e&&e.message||e);
      st.busy=false;
      renderExtRemoteBody();
    }else{
      const tail=document.getElementById('extMoreTail');
      if(tail)tail.textContent='\u52a0\u8f7d\u5931\u8d25\uff0c\u70b9\u6b64\u91cd\u8bd5';
    }
  }finally{
    if(seq===extSeq)st.busy=false;
  }
}
/* ===== ttrgw (天天热瓜) 第五源 ===== */
let tgMode=false, tgTab='v', tgCat='0', tgSort='1';
let tgState=null, tgHomeCache=null, tgHomeP=null, tgSeq=0;
let tgCats={v:[],m:[],p:[]};
let currentTg=null, tgChapters=[], tgChIdx=-1, tgPosTimer=0;
const TG_TABS=[['v','视频'],['m','漫画'],['p','八卦']];
async function tgGet(p){
  const r=await fetch(RELAY_BASE+p,{cache:'no-store'});
  if(!r.ok)throw new Error('HTTP '+r.status);
  const d=await r.json();
  if(d&&d.error)throw new Error(d.error);
  return d;
}
function tgActivate(){
  tgMode=true;extSection=3;
  document.querySelectorAll('.extSeg').forEach(x=>x.classList.toggle('active',x.dataset.seg==='3'));
}
function loadTgHome(){
  if(tgHomeCache)return Promise.resolve(tgHomeCache);
  if(tgHomeP)return tgHomeP;
  tgHomeP=tgGet('/tg/home').then(d=>{
    tgHomeCache=d||{cats:[],hot:[]};
    if(d&&d.catsV&&d.catsV.length)tgCats.v=d.catsV;
    if(d&&d.catsM&&d.catsM.length)tgCats.m=d.catsM;
    if(d&&d.cats&&d.cats.length)tgCats.p=d.cats;
    if(tgMode){renderExtCats();renderExtHot();}
    return tgHomeCache;
  }).catch(()=>{tgHomeP=null;tgHomeCache={cats:[],hot:[]};return tgHomeCache;});
  return tgHomeP;
}
function renderTgTabs(){
  const row=$('tgTabRow');
  if(!row)return;
  row.classList.remove('hidden');
  row.innerHTML='';
  for(const kv of TG_TABS){
    const b=document.createElement('span');
    b.className='extChip'+(tgTab===kv[0]?' active':'');
    b.textContent=kv[1];
    b.addEventListener('click',()=>{
      if(tgTab===kv[0])return;
      tgTab=kv[0];tgCat='0';
      tgState={items:[],page:0,more:true,busy:false,failed:'',kw:''};
      tgSeq++;tgLoad(1);
    });
    row.appendChild(b);
  }
}
function tgCover(container,url){
  if(!url)return;
  const img=document.createElement('img');
  img.loading='lazy';img.alt='';img.referrerPolicy='no-referrer';
  img.src=RELAY_BASE+'/tg/img?u='+encodeURIComponent(url);
  img.onload=()=>{const sp=container.querySelector('span');if(sp)sp.style.display='none';};
  img.onerror=()=>{img.remove();};
  container.insertBefore(img,container.firstChild);
}
function tgCard(it,target){
  const host=target||$('extBody');
  const t=it.type||'v';
  const div=document.createElement('a');
  div.className='extCard '+(t==='v'?'video':t==='m'?'drama':'novel');
  div.href=t==='m'
    ? (mkHref('a',it.id,it.title,'ext')+'&s=tgc')
    : (mkHref('t',it.id,it.title,'ext')+'&k='+t);
  div.innerHTML='<div class="extCover"><span>'+(t==='m'?'📖':'🎞')+'</span><i class="extBadge">'+(t==='m'?'漫画':t==='p'?'八卦':'视频')+'</i></div>'+
    '<div class="extName">'+esc(it.title||'')+'</div>';
  div.addEventListener('click',e=>{
    if(e.metaKey||e.ctrlKey||e.shiftKey||e.altKey||e.button!==0)return;
    e.preventDefault();
    navTo(div.getAttribute('href'),()=>tgOpen(it));
  });
  host.appendChild(div);
  tgCover(div.querySelector('.extCover'),it.cover);
}
function tgOpen(it){
  if(!it)return;
  if((it.type||'v')==='m'){openTgComic(it);return;}
  openTgVideo(it);
}
function tgPaint(){
  const body=$('extBody');
  body.innerHTML='';
  const st=tgState;
  if(!st)return;
  if(!st.items.length){
    const msg=st.failed?('加载失败: '+st.failed+' · 点此重试'):(st.kw?('「'+st.kw+'」暂无结果 · 点此重试'):'暂无内容 · 点此重试');
    body.appendChild(extEmptyRetry(msg,()=>{if(st.busy)return;tgLoad(1);}));
    return;
  }
  for(const it of st.items)tgCard(it);
  if(st.more)renderExtMoreTail();
  else renderExtEndTail();
}
async function tgLoad(page){
  const seq=++tgSeq;
  if(!tgState)tgState={items:[],page:0,more:true,busy:false,failed:'',kw:''};
  const st=tgState;
  if(page<=1){st.items=[];st.page=0;st.more=true;st.failed='';}
  if(st.busy&&page>1)return;
  st.busy=true;
  const body=$('extBody');
  if(page<=1&&!st.items.length)body.innerHTML=emptyHint('加载中...');
  try{
    let d;
    if(st.kw)d=await tgSearchPage(st.kw,page);
    else d=await tgGet('/tg/list?tab='+tgTab+'&cat='+encodeURIComponent(tgCat)+'&sort='+tgSort+'&p='+page);
    if(seq!==tgSeq)return;
    if(d.cats&&d.cats.length){tgCats[tgTab]=d.cats;if(page<=1)renderExtCats();}
    const got=(d.items||[]).filter(x=>x&&x.id&&x.title&&!isBlocked(x.title));
    const have={};
    for(const v of st.items)have[v.id]=1;
    const fresh=[];
    for(const v of got)if(!have[v.id]){have[v.id]=1;st.items.push(v);fresh.push(v);}
    st.page=page;
    st.more=!!d.more;
    if(page>1&&fresh.length){
      const t1=document.getElementById('extMoreTail');if(t1)t1.remove();
      const t2=document.getElementById('extMoreEnd');if(t2)t2.remove();
      for(const v of fresh)tgCard(v);
      if(st.more)renderExtMoreTail();else renderExtEndTail();
    }else{
      tgPaint();
    }
  }catch(e){
    if(seq!==tgSeq)return;
    st.failed=String(e&&e.message||e);
    if(page>1){
      const t3=document.getElementById('extMoreTail');
      if(t3)t3.textContent='加载失败，点此重试';
    }else tgPaint();
  }finally{
    if(seq===tgSeq)st.busy=false;
  }
}
async function tgSearchPage(kw,p){
  const d=await tgGet('/tg/search?kw='+encodeURIComponent(kw)+'&p='+p);
  const items=[];
  if(tgTab!=='m')for(const v of (d.videos||[]))items.push({type:'v',id:v.id,title:v.title,cover:v.cover});
  if(tgTab!=='m')for(const v of (d.posts||[]))items.push({type:'p',id:v.id,title:v.title,cover:v.cover});
  for(const v of (d.comics||[]))items.push({type:'m',id:v.id,title:v.title,cover:v.cover});
  return {items:items,more:!!d.more};
}
function renderTgBody(){
  const body=$('extBody');
  extListMode=true;
  $('extStatus').classList.add('hidden');
  body.classList.remove('hidden');
  $('externalView').setAttribute('data-theme','tg');
  $('extTitle').textContent='天天热瓜';
  renderTgTabs();
  loadTgHome();
  renderExtCats();
  renderExtHot();
  if(tgState&&tgState.items.length){tgPaint();return;}
  if(tgState&&tgState.busy){body.innerHTML=emptyHint('加载中...');return;}
  tgState={items:[],page:0,more:true,busy:false,failed:'',kw:''};
  tgLoad(1);
}
async function openTgVideo(it){
  if(extListMode)saveScroll('externalView');
  extListMode=false;
  extStatusHide();
  extPlaying=null;
  $('extTitle').textContent=it.title||'';
  $('extBody').innerHTML='<div class="loadingHint">解析播放地址...</div>';
  try{
    const d=await tgGet('/tg/detail?t='+(it.type||'v')+'&slug='+encodeURIComponent(it.id));
    if(!d.m3u8)throw new Error('该内容没有视频源');
    openExtPlay(RELAY_BASE+'/tg/hls?u='+encodeURIComponent(d.m3u8),d.name||it.title);
  }catch(e){
    $('extBody').innerHTML='<div class="loadingHint">加载失败: '+esc(e.message)+' · <span id="tgRetryV" style="text-decoration:underline;cursor:pointer">重试</span></div>';
    const b=$('tgRetryV');
    if(b)b.addEventListener('click',()=>openTgVideo(it));
  }
}
function openTgComic(it){
  kpStop();
  currentComic=null;currentAcg=null;
  currentTg={id:it.id,name:it.title||it.name||'',cover:it.cover||''};
  recordHistory('acg',{id:it.id,title:currentTg.name,cover:it.cover,cat:'热瓜',seg:'tgc',type:'c'});
  tgChapters=[];tgChIdx=-1;loadedChapters=[];
  readerTitle.textContent=currentTg.name;
  readerList.innerHTML='<div class="loadingHint">加载章节...</div>';
  $('chapterList').innerHTML='';
  showView('readerView');
  uiTgChapters();
  loadTgComic(it);
}
async function loadTgComic(it){
  try{
    const slug=it.id||it.slug;
    const d=await tgGet('/tg/detail?t=m&slug='+encodeURIComponent(slug));
    currentTg={id:slug,name:d.name||it.title||'',cover:d.cover||it.cover||''};
    recordHistory('acg',{id:slug,title:currentTg.name,cover:currentTg.cover,cat:'热瓜',seg:'tgc',type:'c'});
    tgChapters=(d.chapters||[]).slice();
    if(!tgChapters.length)throw new Error('该作品没有章节');
    uiTgChapters();
    const pos=posOf('g'+slug);
    let idx=0;
    if(pos&&pos.cid){
      const f=tgChapters.findIndex(c=>String(c.id)===String(pos.cid));
      if(f>=0)idx=f;
    }
    const pg=(pos&&String(pos.cid)===String(tgChapters[idx].id))?(pos.page||0):0;
    await tgLoadChapter(idx,pg);
  }catch(e){
    readerList.innerHTML='<div class="loadingHint">加载失败: '+esc(e.message)+'</div>';
  }
}
function uiTgChapters(){
  const list=$('chapterList');
  if(!list)return;
  list.innerHTML='';
  for(let i=0;i<tgChapters.length;i++){
    const ch=tgChapters[i];
    const btn=document.createElement('button');
    btn.className='chapterItem'+(i===tgChIdx?' active':'');
    btn.dataset.cid=ch.id;
    btn.textContent=ch.title||('第'+(i+1)+'话');
    btn.addEventListener('click',()=>{closeChapterPanel();tgLoadChapter(i,0);});
    list.appendChild(btn);
  }
}
function markTgChapter(){
  const btns=document.querySelectorAll('#chapterList .chapterItem');
  for(let i=0;i<btns.length;i++)btns[i].classList.toggle('active',i===tgChIdx);
}
async function tgFetchPages(ch){
  const d=await tgGet('/tg/chapter?id='+encodeURIComponent(ch.id));
  return d.pages||[];
}
async function tgLoadChapter(idx,restorePage){
  const ch=tgChapters[idx];
  if(!ch)return;
  tgChIdx=idx;
  loadedChapters=[];
  readerList.innerHTML='<div class="loadingHint">加载中...</div>';
  try{
    const pages=await tgFetchPages(ch);
    if(!pages.length)throw new Error('该章节无图片');
    readerList.innerHTML='';
    const div=document.createElement('div');
    div.innerHTML='<div class="chapterDivider">'+esc(ch.title||('第'+(idx+1)+'话'))+'</div>';
    const box=document.createElement('div');
    div.appendChild(box);
    readerList.appendChild(div);
    const nm=(currentTg&&currentTg.name)||'';
    let loaded=0;
    for(const u of pages){
      const img=document.createElement('img');
      img.alt='';
      box.appendChild(img);
      setImg(img,RELAY_BASE+'/tg/img?u='+encodeURIComponent(u),()=>{
        loaded++;
        readerTitle.textContent=nm+' '+(loaded+'/'+pages.length);
      });
    }
    loadedChapters.push({id:ch.id,name:ch.title,element:div,total:pages.length});
    readerTitle.textContent=nm+' · '+(ch.title||'');
    markTgChapter();
    if(restorePage>0)restoreScrollTo(box,restorePage);
    tgSavePos();
  }catch(e){
    readerList.innerHTML='<div class="loadingHint">加载失败: '+esc(e.message)+'</div>';
  }
}
async function tgAppendNext(){
  if(loadingChapter)return;
  const ch=tgChapters[tgChIdx+1];
  if(!ch)return;
  loadingChapter=true;
  const hint=document.createElement('div');
  hint.className='loadingHint';hint.textContent='加载下一章...';
  readerList.appendChild(hint);
  try{
    const pages=await tgFetchPages(ch);
    hint.remove();
    if(!pages.length){loadingChapter=false;return;}
    tgChIdx++;
    const div=document.createElement('div');
    div.innerHTML='<div class="chapterDivider">'+esc(ch.title||'')+'</div>';
    const box=document.createElement('div');
    div.appendChild(box);
    readerList.appendChild(div);
    for(const u of pages){
      const img=document.createElement('img');img.alt='';
      box.appendChild(img);setImg(img,RELAY_BASE+'/tg/img?u='+encodeURIComponent(u));
    }
    loadedChapters.push({id:ch.id,name:ch.title,element:div,total:pages.length});
    readerTitle.textContent=((currentTg&&currentTg.name)||'')+' · '+(ch.title||'');
    markTgChapter();
  }catch(e){hint.textContent='加载失败';}
  loadingChapter=false;
}
async function tgPrependPrev(){
  if(loadingChapter)return;
  const ch=tgChapters[tgChIdx-1];
  if(!ch)return;
  loadingChapter=true;
  const hint=document.createElement('div');
  hint.className='loadingHint';hint.textContent='加载上一章...';
  readerList.prepend(hint);
  try{
    const pages=await tgFetchPages(ch);
    hint.remove();
    if(!pages.length){loadingChapter=false;return;}
    tgChIdx--;
    const oldH=readerList.scrollHeight;
    const div=document.createElement('div');
    div.innerHTML='<div class="chapterDivider">'+esc(ch.title||'')+'</div>';
    const box=document.createElement('div');
    div.appendChild(box);
    const imgs=[];
    for(const u of pages){
      const img=document.createElement('img');img.alt='';
      box.appendChild(img);imgs.push(img);setImg(img,RELAY_BASE+'/tg/img?u='+encodeURIComponent(u));
    }
    readerList.prepend(div);
    loadedChapters.unshift({id:ch.id,name:ch.title,element:div,total:pages.length});
    Promise.all(imgs.map(i=>new Promise(res=>{if(i.complete)res();else{i.onload=res;i.onerror=res;}}))).then(()=>{
      requestAnimationFrame(()=>{const nh=readerList.scrollHeight;readerList.scrollTop=nh-oldH;});
    });
    readerTitle.textContent=((currentTg&&currentTg.name)||'')+' · '+(ch.title||'');
    markTgChapter();
  }catch(e){hint.textContent='加载失败';}
  loadingChapter=false;
}
function setupTgReaderScroll(){
  readerList.onscroll=()=>{
    if(restoringPos)return;
    if(!loadingChapter){
      if(readerList.scrollTop+readerList.clientHeight>=readerList.scrollHeight-260)tgAppendNext();
      if(readerList.scrollTop<10&&tgChIdx>0)tgPrependPrev();
    }
    tgSavePos();
  };
}
function tgSavePos(force){
  if(!currentTg||!readerList)return;
  if(readerList.classList.contains('hidden'))return;
  const run=()=>{
    tgPosTimer=0;
    if(!currentTg)return;
    const rect=readerList.getBoundingClientRect();
    if(rect.width===0||rect.height===0)return;
    const imgs=readerList.querySelectorAll('img');
    let page=0;
    for(let i=0;i<imgs.length;i++){if(imgs[i].getBoundingClientRect().top-rect.top<=120)page=i;else break;}
    const ch=tgChapters[tgChIdx];
    setPos('g'+currentTg.id,{cid:ch?ch.id:'',name:ch?ch.title:'',page:page,ts:Date.now()});
  };
  if(force){if(tgPosTimer){clearTimeout(tgPosTimer);tgPosTimer=0;}run();return;}
  if(tgPosTimer)return;
  tgPosTimer=setTimeout(run,600);
}

const KJ_BUILD='v19';
console.log('KJ build '+KJ_BUILD);
function renderExternal(){extListMode=true;renderExternalBody();restoreScrollSoon('externalView');}
function renderExternalBody(){
  if(tgMode){renderTgBody();return;}
  const _ttr=$('tgTabRow');if(_ttr)_ttr.classList.add('hidden');
  const body=$('extBody');
  $('extStatus').classList.add('hidden');
  body.classList.remove('hidden');
  $('externalView').setAttribute('data-theme',extTheme());
  renderExtCats();
  renderExtHot();
  if(extSection===1&&extIsContentCat(extCat)){
    if(extRemote&&extRemote.mode==='cat'&&extRemote.key===extCat)renderExtRemoteBody();
    else extLocalStart(extCat);
    return;
  }
  if(extSection===1&&extKwRemote){
    if(extRemote&&extRemote.mode==='kw'&&extRemote.key===extKwRemote)renderExtRemoteBody();
    else extRemoteStart('kw',extKwRemote);
    return;
  }
  if(!extData){body.innerHTML=emptyHint('\u6b63\u5728\u52a0\u8f7d...');return;}
  body.innerHTML='';
  let list;
  if(extSection===0)list=extData.dramas;
  else if(extSection===1)list=extData.videos;
  else list=extData.novels;
  if(extSection===1&&!extCat)list=list.filter(x=>!extIsContentCat(x.cat));
  if(extCat)list=list.filter(x=>x.cat===extCat);
  if(extKw)list=list.filter(x=>x.name.toLowerCase().includes(extKw));
  if(list.length===0){body.innerHTML=emptyHint(extSection===0?'\u6682\u65e0\u77ed\u5267':extSection===1?'\u6682\u65e0\u89c6\u9891':'\u6682\u65e0\u5c0f\u8bf4');return;}
  for(const it of list){
    if(extSection===0)renderExtDramaCard(it);
    else if(extSection===1)renderExtVideoCard(it);
    else renderExtNovelCard(it);
  }
}
function renderExtDramaCard(d){
  const div=document.createElement('a');
  div.className='extCard drama';
  div.href=mkHref('d',d.id,d.name,'ext');
  div.innerHTML='<div class="extCover"><span>\ud83c\udfac</span><i class="extBadge">'+esc(d.cat||'\u77ed\u5267')+'</i></div>'+
    '<div class="extName">'+esc(d.name)+'</div>';
  div.addEventListener('click',e=>{
    if(e.metaKey||e.ctrlKey||e.shiftKey||e.altKey||e.button!==0)return;
    e.preventDefault();
    navTo(div.getAttribute('href'),()=>openExtDrama(d));
  });
  $('extBody').appendChild(div);
  extCover(div.querySelector('.extCover'),d.cover);
}
function renderExtVideoCard(v){
  const div=document.createElement('a');
  div.className='extCard video';
  div.href=mkHref('x',v.key,v.name,'ext');
  div.innerHTML='<div class="extCover"><span>\ud83c\udf9e\ufe0f</span><i class="extBadge">'+esc(v.cat||'\u89c6\u9891')+'</i></div>'+
    '<div class="extName">'+esc(v.name)+'</div>';
  div.addEventListener('click',e=>{
    if(e.metaKey||e.ctrlKey||e.shiftKey||e.altKey||e.button!==0)return;
    e.preventDefault();
    navTo(div.getAttribute('href'),()=>openExtVideo(v));
  });
  $('extBody').appendChild(div);
  extCover(div.querySelector('.extCover'),v.cover);
}
function renderExtNovelCard(n){
  const div=document.createElement('a');
  div.className='extCard novel';
  div.href=mkHref('e',n.id,n.name,'ext');
  div.innerHTML='<div class="extCover novel"><span>\ud83d\udcd6</span><i class="extBadge">'+esc(n.cat||'\u5c0f\u8bf4')+'</i></div>'+
    '<div class="extName">'+esc(n.name)+'</div>';
  div.addEventListener('click',e=>{
    if(e.metaKey||e.ctrlKey||e.shiftKey||e.altKey||e.button!==0)return;
    e.preventDefault();
    navTo(div.getAttribute('href'),()=>openExtNovel(n));
  });
  $('extBody').appendChild(div);
}
async function openExtDrama(d){
  if(extListMode)saveScroll('externalView');
  extListMode=false;
  extStatusHide();
  $('extTitle').textContent=d.name;
  $('extBody').innerHTML='<div class="loadingHint">加载剧集...</div>';
  try{
    const r=await fetch(RELAY_BASE+'/drama?id='+encodeURIComponent(d.id));
    const j=await r.json();
    if(j.error)throw new Error(j.error);
    renderExtEpisodes(d,j);
  }catch(e){$('extBody').innerHTML='<div class="loadingHint">加载失败: '+esc(e.message)+'</div>';}
}
function renderExtEpisodes(d,detail){
  const body=$('extBody');
  body.innerHTML='';
  const head=document.createElement('div');
  head.className='extDetailHead';
  head.innerHTML='<button class="chip">← 返回</button><span class="extDetailTitle">'+esc(detail.name||d.name)+'（共'+(detail.total||detail.episodes.length)+'集）</span>';
  head.querySelector('button').addEventListener('click',()=>goBack(()=>renderExternal()));
  body.appendChild(head);
  const grid=document.createElement('div');
  grid.className='extEpGrid';
  for(const ep of detail.episodes){
    const b=document.createElement('button');
    b.className='extEp';b.textContent='第'+ep+'集';
    b.addEventListener('click',()=>playExtDrama(d.id,ep,detail.name||d.name,detail.episodes));
    grid.appendChild(b);
  }
  body.appendChild(grid);
}
async function playExtDrama(id,ep,title,episodes){
  extStatusHide();
  const eps=(episodes&&episodes.length)?episodes.slice():[ep];
  let idx=eps.indexOf(ep);
  if(idx<0){eps.push(ep);idx=eps.length-1;}
  extPlaying={id:id,name:title,episodes:eps,idx:idx};
  try{history.pushState({kjDetail:1,kjPlaying:1},' ',location.hash||'#/ext');}catch(e){}
  $('extBody').innerHTML='<div class="loadingHint">解析播放地址...</div>';
  try{
    const r=await fetch(RELAY_BASE+'/resolve?type=51dbe&id='+encodeURIComponent(id)+'&ep='+encodeURIComponent(ep));
    const j=await r.json();
    if(j.error||!j.m3u8)throw new Error(j.error||'解析失败');
    openExtPlay(j.m3u8, title+' 第'+ep+'集');
  }catch(e){extPlaying=null;$('extBody').innerHTML='<div class="loadingHint">加载失败: '+esc(e.message)+'</div>';}
}
async function openExtVideo(v){
  if(extListMode)saveScroll('externalView');
  extListMode=false;
  extStatusHide();
  extPlaying=null;
  $('extTitle').textContent=v.name;
  $('extBody').innerHTML='<div class="loadingHint">解析播放地址...</div>';
  try{
    const r=await fetch(RELAY_BASE+'/resolve?type=91&key='+encodeURIComponent(v.key));
    const j=await r.json();
    if(j.error||!j.m3u8)throw new Error(j.error||'解析失败');
    openExtPlay(j.m3u8, v.name);
  }catch(e){$('extBody').innerHTML='<div class="loadingHint">加载失败: '+esc(e.message)+'</div>';}
}
async function openExtNovel(n){
  if(extListMode)saveScroll('externalView');
  extListMode=false;
  extStatusHide();
  $('extTitle').textContent=n.name;
  $('extBody').innerHTML='<div class="loadingHint">加载正文...</div>';
  try{
    const r=await fetch(RELAY_BASE+'/novel?id='+encodeURIComponent(n.id));
    const j=await r.json();
    if(j.error)throw new Error(j.error);
    renderExtNovel(n,j);
  }catch(e){$('extBody').innerHTML='<div class="loadingHint">加载失败: '+esc(e.message)+'</div>';}
}
function renderExtNovel(n,data){
  const body=$('extBody');
  body.innerHTML='';
  const head=document.createElement('div');
  head.className='extDetailHead';
  head.innerHTML='<button class="chip">← 返回</button><span class="extDetailTitle">'+esc(data.title||n.name)+'</span>';
  head.querySelector('button').addEventListener('click',()=>goBack(()=>renderExternal()));
  body.appendChild(head);
  const wrap=document.createElement('div');
  wrap.className='extNovelBody';
  const paras=(data.content||'').split(/\n\n+/).filter(p=>p.trim());
  if(paras.length===0)wrap.innerHTML='<div class="loadingHint">无正文</div>';
  else for(const p of paras){const pe=document.createElement('p');pe.textContent=p;wrap.appendChild(pe);}
  body.appendChild(wrap);
}
/* ===== 播放器 · 短剧选集 / 上一集 / 下一集 ===== */
function plNavLock(on){
  ['plPrev','plList','plNext'].forEach(id=>{const b=$(id);if(!b)return;b.disabled=on;b.style.opacity=on?'0.35':'';});
}
function plSetNavVisible(v){
  const nav=$('playerNav');if(!nav)return;
  nav.classList.toggle('hidden',!v);
  if(!v)$('playerEpPanel').classList.add('hidden');
}
function plUpdateNav(){
  if(!extPlaying)return;
  const eps=extPlaying.episodes,i=extPlaying.idx,n=eps.length;
  const prev=$('plPrev'),next=$('plNext'),list=$('plList'),head=$('playerEpTitle');
  if(!prev||!next||!list)return;
  const atHead=i<=0,atTail=i>=n-1;
  prev.disabled=atHead;prev.style.opacity=atHead?'0.35':'';
  next.disabled=atTail;next.style.opacity=atTail?'0.35':'';
  list.textContent='选集 '+eps[i]+'/'+n;
  if(head)head.textContent=extPlaying.name+' · 共 '+n+' 集';
}
function plBuildList(){
  const box=$('playerEpList');if(!box||!extPlaying)return;
  box.innerHTML='';
  extPlaying.episodes.forEach((ep,i)=>{
    const b=document.createElement('button');
    b.className='plEp'+(i===extPlaying.idx?' active':'');
    b.textContent='第'+ep+'集';
    b.addEventListener('click',()=>{
      $('playerEpPanel').classList.add('hidden');
      if(i!==extPlaying.idx)plSwitch(i);
    });
    box.appendChild(b);
  });
  const cur=box.querySelector('.plEp.active');
  if(cur)setTimeout(()=>{try{cur.scrollIntoView({block:'center'});}catch(e){}},40);
}
async function plSwitch(i){
  if(!extPlaying)return;
  const eps=extPlaying.episodes;
  if(i<0||i>=eps.length)return;
  plNavLock(true);
  playerStatus.textContent='正在解析第 '+eps[i]+' 集...';
  try{
    const r=await fetch(RELAY_BASE+'/resolve?type=51dbe&id='+encodeURIComponent(extPlaying.id)+'&ep='+encodeURIComponent(eps[i]));
    const j=await r.json();
    if(j.error||!j.m3u8)throw new Error(j.error||'解析失败');
    extPlaying.idx=i;
    playerTitle.textContent=extPlaying.name+' 第'+eps[i]+'集';
    plUpdateNav();plBuildList();
    await plPlay(j.m3u8);
  }catch(e){
    playerStatus.textContent='第 '+eps[i]+' 集播放失败: '+e.message;
  }finally{
    plNavLock(false);plUpdateNav();
  }
}
async function plPlay(hlsUrl){
  try{
    if(!hlsUrl)throw new Error('解析失败');
    playerStatus.textContent='';
    if(videoEl._hls){try{videoEl._hls.destroy();}catch(e){}videoEl._hls=null;}
    videoEl.pause();
    videoEl.removeAttribute('src');
    try{videoEl.load();}catch(e){}
    const isApple=/iPad|iPhone|iPod/.test(navigator.userAgent)||(navigator.userAgent.indexOf('Mac')>=0&&navigator.maxTouchPoints>1);
    // Chrome/Edge 对 apple.mpegurl 会返回 "maybe" 但实际放不了 HLS, 只信 Safari/iOS
    const canNative=isApple;
    if(canNative){
      // iOS/Safari 原生 HLS 只认 .m3u8 后缀, worker 侧有同名别名路由
      let nsrc=hlsUrl;
      if(/\/hls\?/.test(nsrc))nsrc=nsrc.replace('/hls?','/hls.m3u8?');
      videoEl.src=nsrc;
      videoEl.play().catch(()=>{});
      return;
    }
    await ensureHls();
    if(window.Hls&&window.Hls.isSupported()){
      const hls=new window.Hls({
        startLevel:-1,
        maxBufferLength:120,
        maxMaxBufferLength:300,
        maxBufferSize:256*1024*1024,
        manifestLoadingTimeOut:20000,
        fragLoadingTimeOut:60000,
        fragLoadingMaxRetry:8,
        fragLoadingRetryDelay:300,
        enableWorker:true,
        abrEwmaDefaultEstimate:1200000
      });
      hls.loadSource(hlsUrl);
      hls.attachMedia(videoEl);
      hls.on(window.Hls.Events.MANIFEST_PARSED,()=>{videoEl.play().catch(()=>{});});
      hls.on(window.Hls.Events.ERROR,(ev,data)=>{
        if(data.fatal){playerStatus.textContent='播放错误: '+data.details;hls.destroy();}
      });
      videoEl._hls=hls;
    }else{
      playerStatus.textContent='浏览器不支持 HLS 播放';
    }
  }catch(e){playerStatus.textContent='播放失败: '+e.message;}
}
async function openExtPlay(hlsUrl,title){
  playerReturn='externalView';
  playerTitle.textContent=title;
  playerStatus.textContent='获取播放地址...';
  showView('playerView');
  plSetNavVisible(!!extPlaying);
  if(extPlaying){plUpdateNav();plBuildList();$('playerEpPanel').classList.add('hidden');}
  await plPlay(hlsUrl);
}
document.querySelectorAll('.extSeg').forEach(b=>{
  b.addEventListener('click',()=>{
    extSection=parseInt(b.dataset.seg);
    tgMode=(extSection===3);
    extCat=null;extRemote=null;extKwRemote=null;extKw='';extSeq++;
    if(tgMode){tgCat='0';tgState=null;tgSeq++;}
    const _si=$('extSearchInput');if(_si)_si.value='';
    document.querySelectorAll('.extSeg').forEach(x=>x.classList.toggle('active',x===b));
    extListMode=true;resetExtScroll();
    renderExternal();
  });
});
$('extBack').addEventListener('click',()=>{
  const st=history.state||{};
  if(st.kjFromTab){history.back();return;}
  switchMode(lastTabMode);
});
function extDoSearch(){
  extListMode=true;resetExtScroll();
  if(tgMode){
    const tv=($('extSearchInput').value||'').trim();
    tgState={items:[],page:0,more:true,busy:false,failed:'',kw:tv};
    tgSeq++;tgLoad(1);
    return;
  }
  const v=($('extSearchInput').value||'').trim();
  if(extSection!==1){extKw=v.toLowerCase();renderExternal();return;}
  if(!v){extKwRemote=null;extKw='';extCat=null;extRemote=null;extSeq++;renderExternal();return;}
  extKw=v.toLowerCase();
  extCat=null;
  extRemote=null;
  extKwRemote=v;
  renderExternal();
}
$('extSearchInput').addEventListener('input',()=>{
  if(tgMode){extListMode=true;resetExtScroll();return;}
  extListMode=true;resetExtScroll();
  const v=$('extSearchInput').value.trim();
  extKw=v.toLowerCase();
  if(extSection!==1){renderExternal();return;}
  if(!v){extKwRemote=null;extRemote=null;extSeq++;renderExternal();return;}
  if(extKwRemote)return;
  if(extCat){extCat=null;extRemote=null;extSeq++;}
  renderExternal();
});
$('extSearchInput').addEventListener('keydown',e=>{if(e.key==='Enter'){e.preventDefault();extDoSearch();}});
(function(){const sb=$('extSearchBtn');if(sb)sb.addEventListener('click',extDoSearch);})();
$('extBody').addEventListener('scroll',()=>{
  if(tgMode){
    const el0=$('extBody');
    if(tgState&&tgState.more&&!tgState.busy&&el0.scrollTop+el0.clientHeight>=el0.scrollHeight-320)tgLoad(tgState.page+1);
    return;
  }
  if(Date.now()<scrollGuardUntil)return;
  const el=$('extBody');
  if(!extRemote||!extRemote.more||extRemote.busy)return;
  if(el.scrollTop+el.clientHeight>=el.scrollHeight-320)extRemoteNext(extSeq);
},{passive:true});


$('plPrev').addEventListener('click',()=>{if(extPlaying)plSwitch(extPlaying.idx-1);});
$('plNext').addEventListener('click',()=>{if(extPlaying)plSwitch(extPlaying.idx+1);});
$('plList').addEventListener('click',()=>{if(!extPlaying)return;plBuildList();$('playerEpPanel').classList.toggle('hidden');});
$('playerEpClose').addEventListener('click',()=>$('playerEpPanel').classList.add('hidden'));
videoEl.addEventListener('ended',()=>{
  if(extPlaying&&extPlaying.idx<extPlaying.episodes.length-1)plSwitch(extPlaying.idx+1);
});

/* ===== hash routes ===== */
function mkHref(k,id,name,b){return '#/'+k+'/'+encodeURIComponent(id)+'?n='+encodeURIComponent(name||'')+'&b='+b;}
function navTo(hash,opener){
  if(location.hash===hash){opener();return;}
  try{history.pushState({kjDetail:1},' ',hash);}catch(e){}
  opener();
}
function goBack(fallback){
  const st=history.state||{};
  if(st.kjDetail||st.kjFromTab){history.back();return;}
  if(typeof fallback==='function')fallback();
}
function parseQS(q){
  const o={};
  if(!q)return o;
  for(const p of q.split('&')){
    if(!p)continue;
    const i=p.indexOf('=');
    const k=i<0?p:p.slice(0,i);
    const v=i<0?'':p.slice(i+1);
    try{o[k]=decodeURIComponent(v.replace(/\+/g,' '));}catch(e){o[k]=v;}
  }
  return o;
}
function syncHash(target){
  try{
    if(location.hash===target)return;
    if(target==='#/ext'&&/^#\/m\/\d+$/.test(location.hash))history.pushState({kjBase:1,kjFromTab:1},' ',target);
    else history.replaceState({kjBase:1},' ',target);
  }catch(e){}
}
function applyRoute(){
  const h=location.hash||'';
  let m;
  if(h==='#/ext'){extListMode=true;openExternal();return;}
  if((m=/^#\/m\/(\d+)$/.exec(h))){
    const n=parseInt(m[1]);
    if(n===mode&&grid.children.length>0){showView('mainView');restoreScrollSoon('mainView');}
    else{switchMode(n);if(currentViewId()!=='mainView')showView('mainView');}
    return;
  }
  if((m=/^#\/([cvfndxeat])\/([^?]+)(?:\?(.*))?$/.exec(h))){
    let id=m[2];try{id=decodeURIComponent(id);}catch(e){}
    const q=parseQS(m[3]||'');
    openFromRoute(m[1],id,q.n||'',q);
    return;
  }
  switchMode(0);
}
function openFromRoute(k,id,name,q){
  if(k==='t'){
    tgActivate();
    if($('externalView').classList.contains('hidden')){extListMode=false;showView('externalView');}
    tgOpen({id:id,title:name,type:(q&&q.k)||'v'});
    return;
  }
  if(k==='a'){
    const seg=(q&&q.s)||'h';
    openAcgComic({id:id,title:name,seg:seg,type:(seg==='gif'?'v':'c')});
    return;
  }
  if(k==='c'){openComic({id:id,name:name});return;}
  if(k==='v'){openVod({vod_id:id,vod_name:name});return;}
  if(k==='f'){openForum({id:id,title:name,hits:0,boardName:''});return;}
  if(k==='n'){openNovel({id:id,name:name});return;}
  if($('externalView').classList.contains('hidden')){extListMode=false;showView('externalView');}
  if(k==='d'){openExtDrama({id:id,name:name});return;}
  if(k==='x'){openExtVideo({key:id,name:name});return;}
  openExtNovel({id:id,name:name});
}
window.addEventListener('popstate',()=>{applyRoute();});

/* ===== init ===== */
if('serviceWorker' in navigator){
  navigator.serviceWorker.register('sw.js').catch(()=>{});
}
(function boot(){
  const h=location.hash||'';
  if(/^#\/([cvfndxeat])\//.test(h)){
    const q=parseQS(h.indexOf('?')>=0?h.slice(h.indexOf('?')+1):'');
    const parent=(q.b==='ext')?'#/ext':('#/m/'+((q.b!==undefined&&q.b!=='')?q.b:'0'));
    try{history.replaceState({kjBase:1},' ',parent);history.pushState({kjDetail:1},' ',h);}catch(e){}
    applyRoute();
    return;
  }
  if(!h||h==='#'||h==='#/'){try{history.replaceState({kjBase:1},' ','#/m/0');}catch(e){}}
  applyRoute();
})();
