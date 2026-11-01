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
async function loadXorImage(url){
  if(imgCache.has(url))return imgCache.get(url);
  let lastErr=null;
  for(let attempt=0;attempt<3;attempt++){
    try{
      const resp=await fetch(url,{cache:'force-cache'});
      if(!resp.ok)throw new Error('HTTP '+resp.status);
      const buf=await resp.arrayBuffer();
      const arr=new Uint8Array(buf);
      for(let i=0;i<arr.length;i++)arr[i]^=0x88;
      const blob=new Blob([arr],{type:'image/jpeg'});
      const objUrl=URL.createObjectURL(blob);
      imgCache.set(url,objUrl);
      return objUrl;
    }catch(e){
      lastErr=e;
      await new Promise(r=>setTimeout(r,400*(attempt+1)));
    }
  }
  throw lastErr;
}
function resolveImgUrl(pic){
  if(!pic)return null;
  if(pic.startsWith('http'))return pic;
  if(pic.startsWith('/'))return IMG_CDN+pic.substring(1);
  return IMG_CDN+pic;
}
const BLOCK_STRICT=['人兽','兽交','兽奸','动物交','马交','马肛','马屌','疯马','与马','狗交','犬交','疯狗','狗屌','猪交','触手','幼女','幼交','未成年','儿童','萝莉','乱伦','男同','同性恋','gay','骚受','伪娘','肛交','爆肛','操肛','后庭','重口味','重口','猎奇','血腥','尸体','欧美','老外','洋屌','黑屌','媚黑','人妖','变性','手淫','自慰','打飞机','飞机杯','换脸'];
const BLOCK_NAME=['人兽','兽交','兽迷','兽人','兽奸','动物','动物园','动物交','幼女','幼交','未成年','乱伦','萝莉','儿童','畜生','男同','同性','同志','gay','骚受','伪娘','人妖','变性','肛交','爆肛','操肛','菊花','后庭','重口味','欧美','老外','洋屌','黑屌','媚黑','手淫','自慰','打飞机','飞机杯','疯马','马交','马肛','马屌','马鸡','野马','与马','疯狗','狗交','狗鸡','狗屌','母狗','犬交','猪射','触手','狗狗'];
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
const $=id=>document.getElementById(id);
const grid=$('grid'),loadMore=$('loadMore'),searchInput=$('searchInput');
const catPanel=$('catPanel'),hotChips=$('hotChips'),catClassChips=$('catClassChips'),catTagChips=$('catTagChips'),catChildChips=$('catChildChips');
const catClassRow=$('catClassRow'),catTagRow=$('catTagRow'),catChildRow=$('catChildRow');
const readerView=$('readerView'),readerList=$('readerList'),readerTitle=$('readerTitle');
const playerView=$('playerView'),videoEl=$('videoEl'),playerStatus=$('playerStatus'),playerTitle=$('playerTitle');
const forumView=$('forumView'),forumBody=$('forumBody'),forumTitle=$('forumTitle');
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
  document.querySelectorAll('.tab').forEach(b=>b.classList.toggle('active',parseInt(b.dataset.mode)===m));
  searchInput.value='';
  catPanel.classList.add('hidden');catPanelOpen=false;
  comicPage=1;comicEnd=false;comicKw='';comicKwMode=false;
  vodPage=1;vodEnd=false;vodKw='';vodKwMode=false;
  forumPage=1;forumEnd=false;forumKw='';forumKwMode=false;
  comicCid='';comicTid='';vodType='';vodPid='';forumBid='';
  grid.innerHTML='';
  loadMore.classList.add('hidden');
  reloadCats();
  doLoad(true);
}
$('searchBtn').addEventListener('click',doSearch);
searchInput.addEventListener('keydown',e=>{if(e.key==='Enter')doSearch();});
function doSearch(){
  const kw=searchInput.value.trim();
  if(mode===0){comicKw=kw;comicKwMode=!!kw;comicPage=1;comicEnd=false;}
  else if(mode===1){vodKw=kw;vodKwMode=!!kw;vodPage=1;vodEnd=false;}
  else{forumKw=kw;forumKwMode=!!kw;forumPage=1;forumEnd=false;}
  grid.innerHTML='';
  doLoad(true);
}
$('catBtn').addEventListener('click',()=>{
  catPanelOpen=!catPanelOpen;
  catPanel.classList.toggle('hidden',!catPanelOpen);
});
let comicClassesData=[],comicTagsData=[],vodTypesData=[],forumBoardsData=[];
async function reloadCats(){
  catClassChips.innerHTML='';catTagChips.innerHTML='';catChildChips.innerHTML='';
  catClassRow.classList.add('hidden');catTagRow.classList.add('hidden');catChildRow.classList.add('hidden');
  hotChips.innerHTML='';
  try{
    if(mode===0){
      catClassRow.classList.remove('hidden');catTagRow.classList.remove('hidden');
      const r=await apiCall('/v2/api/comic/condition',{});
      const d=r.data||{};
      comicClassesData=(d.class||[]).filter(c=>c.name&&c.id&&c.name!=='全部'&&!c.name.includes('欧美')&&!c.name.includes('同性')&&!nameBlocked(c.name));
      comicTagsData=(d.tags||[]).filter(t=>t.name&&t.id&&t.name!=='全部'&&!t.name.includes('欧美')&&!t.name.includes('同性')&&!nameBlocked(t.name));
      const seen=new Set();comicClassesData=comicClassesData.filter(c=>{if(seen.has(c.name))return false;seen.add(c.name);return true;});
      const seenT=new Set();comicTagsData=comicTagsData.filter(t=>{if(seenT.has(t.name))return false;seenT.add(t.name);return true;});
      buildChips(catClassChips,comicClassesData,'cid',()=>{comicCid='';});
      buildChips(catTagChips,comicTagsData,'tid',()=>{comicTid='';});
      const hr=await apiCall('/v2/api/comic/hotSearch',{});
      const hw=(hr.data&&hr.data.hot_keyword)||[];
      buildHot(hw);
    }else if(mode===1){
      catClassRow.classList.remove('hidden');catChildRow.classList.remove('hidden');
      const r=await apiCall('/api/app/vodClass',{});
      const d=r.data||{};
      vodTypesData=(d.type||[]).filter(t=>String(t.id)&&t.name&&t.name!=='全部'&&!['4','73','8'].includes(String(t.id))&&!nameBlocked(t.name));
      buildChips(catClassChips,vodTypesData.map(t=>({id:String(t.id),name:t.name})),'vpid',()=>{vodPid='';vodType='';});
      const hr=await apiCall('/api/app/hotSearch',{});
      const hd=hr.data||[];
      let hw=[];
      if(Array.isArray(hd))for(const o of hd){const list=o.list||[];for(const k of list){const w=k.vod_name||'';if(w&&!isBlocked(w)&&!hotBad(w)){hw.push(w);if(hw.length>=20)break;}}if(hw.length>=20)break;}
      buildHot(hw);
    }else{
      catClassRow.classList.remove('hidden');
      const r=await apiCall('/v2/api/forum/index',{id:1});
      const d=r.data||{};
      const child=(d.board&&d.board.child)||[];
      forumBoardsData=child.filter(b=>b.name&&b.name!=='全部'&&!isBlocked(b.name)).map(b=>({id:String(b.id),name:b.name}));
      buildChips(catClassChips,[{id:'0',name:'最新'},...forumBoardsData],'bid',()=>{forumBid='0';});
      try{
        const hr=await apiCall('/v2/api/forum/hotSearch',{});
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
    if(key==='cid')comicCid='';
    if(key==='tid')comicTid='';
    if(key==='vpid'){vodPid='';vodType='';catChildChips.innerHTML='';}
    if(key==='bid')forumBid='';
    doLoad(true);
  });
  container.appendChild(all);
  for(const item of items){
    const chip=document.createElement('span');
    chip.className='chip';chip.textContent=item.name;
    chip.addEventListener('click',()=>{
      container.querySelectorAll('.chip').forEach(c=>c.classList.remove('active'));
      chip.classList.add('active');
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
        const r2=await apiCall('/api/app/vodList',{type:vodType,type_pid:vodPid,class:'',sort:'rand',page:vodPage});
        raw2=(r2.data||{}).list||[];
      }
      items=raw2.filter(v=>v.vod_name&&!nameBlocked(v.vod_name)&&v.type_id!==4);
      if(raw2.length<10)vodEnd=true;
    }else{
      if(forumKwMode){
        const r3=await apiCall('/v2/api/forum/searchList',{wd:forumKw,page:forumPage});
        items=parseForumList(r3);
      }else{
        const r3=await apiCall('/v2/api/forum/list',{bid:forumBid,uid:'',type:'',page:forumPage});
        items=parseForumList(r3);
      }
      if(forumRawCount<10)forumEnd=true;
    }
    if(reset)grid.innerHTML='';
    renderItems(items);
  }catch(e){
    if(reset)grid.innerHTML='';
    showToast('加载失败: '+e.message);
  }finally{
    loading=false;
    if((mode===0&&comicEnd)||(mode===1&&vodEnd)||(mode===2&&forumEnd)){
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
    else renderForumCard(item);
  }
}
function renderComicCard(c){
  const div=document.createElement('div');
  div.className='card';
  const coverUrl=resolveImgUrl(c.pic);
  div.innerHTML='<div class="cover"><span>\uD83D\uDCD6</span>'+(c.pay===2?'<span class="badge">VIP</span>':'')+'</div>'+
    '<div class="info"><div class="name">'+esc(c.name)+'</div><div class="sub">'+(c.latest_chapter_name?'更新至 '+esc(c.latest_chapter_name):'连载中')+'</div></div>';
  div.addEventListener('click',()=>openComic(c));
  grid.appendChild(div);
  if(coverUrl)lazyImg(div.querySelector('.cover'),coverUrl);
}
function renderVodCard(v){
  const div=document.createElement('div');
  div.className='card';
  const coverUrl=resolveImgUrl(v.vod_pic);
  const hd=v.vod_mode?'HD':'';
  div.innerHTML='<div class="cover"><span>\uD83C\uDFAC</span>'+(hd?'<span class="badge">'+hd+'</span>':'')+(v.vod_duration?'<span class="dur">'+esc(v.vod_duration)+'</span>':'')+'</div>'+
    '<div class="info"><div class="name">'+esc(v.vod_name)+'</div><div class="sub">'+(v.vod_duration?'时长 '+esc(v.vod_duration):'')+'</div></div>';
  div.addEventListener('click',()=>openVod(v));
  grid.appendChild(div);
  if(coverUrl)lazyImg(div.querySelector('.cover'),coverUrl);
}
function renderForumCard(f){
  const div=document.createElement('div');
  div.className='card';
  const coverUrl=f.cover?resolveImgUrl(f.cover):null;
  div.innerHTML='<div class="cover"><span>\uD83D\uDCAC</span></div>'+
    '<div class="info"><div class="name">'+esc(f.title)+'</div><div class="sub">'+esc(f.boardName)+' · '+f.hits+'阅</div></div>';
  div.addEventListener('click',()=>openForum(f));
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
/* ===== infinite scroll ===== */
window.addEventListener('scroll',()=>{
  if($('mainView').classList.contains('hidden'))return;
  if(loading)return;
  if((mode===0&&comicEnd)||(mode===1&&vodEnd)||(mode===2&&forumEnd))return;
  if(window.innerHeight+window.scrollY>=document.body.offsetHeight-300){
    if(mode===0){comicPage++;doLoad(false);}
    else if(mode===1){vodPage++;doLoad(false);}
    else{forumPage++;doLoad(false);}
  }
});
/* ===== comic reader ===== */
let chaptersCache=[],loadedChapters=[],currentChapterIdx=-1,loadingChapter=false;
async function openComic(comic){
  currentComic=comic;
  readerTitle.textContent=comic.name;
  readerList.innerHTML='<div class="loadingHint">加载章节...</div>';
  showView('readerView');
  try{
    await ensureLogin();
    const r=await apiCall('/v2/api/comic/chapter',{mid:comic.id,id:''});
    const d=r.data||{};
    chaptersCache=(d.chapter||[]).map(c=>({id:c.id,name:c.name,pay:c.pay||0,bullion:c.bullion||0}));
    renderChapterButtons();
    if(chaptersCache.length>0)loadChapterPages(chaptersCache[0].id,chaptersCache[0].name,chaptersCache[0].pay);
    else readerList.innerHTML='<div class="loadingHint">无章节</div>';
  }catch(e){
    readerList.innerHTML='<div class="loadingHint">加载失败: '+esc(e.message)+'</div>';
  }
}
function renderChapterButtons(){
  const div=document.createElement('div');
  div.className='chapterDivider';
  div.textContent='共 '+chaptersCache.length+' 章 · 点击章节名跳转';
  readerList.innerHTML='';
  readerList.appendChild(div);
  const wrap=document.createElement('div');
  wrap.style.cssText='display:flex;flex-wrap:wrap;gap:6px;padding:10px;justify-content:center;';
  for(const ch of chaptersCache){
    const btn=document.createElement('button');
    btn.className='chip';btn.textContent=ch.name+(ch.pay!==0?' \uD83D\uDD12':'');
    btn.addEventListener('click',()=>loadChapterPages(ch.id,ch.name,ch.pay));
    wrap.appendChild(btn);
  }
  readerList.appendChild(wrap);
}
async function loadChapterPages(cid,cname,pay){
  if(loadingChapter)return;
  loadingChapter=true;
  readerList.innerHTML='<div class="loadingHint">加载中...</div>';
  loadedChapters=[];
  currentChapterIdx=chaptersCache.findIndex(c=>c.id===cid);
  try{
    const pages=await getChapterPages({id:cid,name:cname,pay:pay});
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
      loadXorImage(url).then(src=>{
        img.src=src;loaded++;
        readerTitle.textContent=cname+' ('+loaded+'/'+pages.length+')';
      }).catch(()=>{loaded++;});
    }
    loadedChapters.push({id:cid,name:cname,pay,element:chapterDiv});
    readerTitle.textContent=cname;
    setupReaderScroll();
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
async function enumeratePages(firstPath,cdn){
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
    const lo=scanStart,hi=Math.min(maxPage,scanStart+batch-1);
    const probes=[];
    for(let n=lo;n<=hi;n++)probes.push(probePage(dir,n));
    const settled=await Promise.allSettled(probes);
    let found=0;
    for(let i=0;i<settled.length;i++){
      if(settled[i].status==='fulfilled'&&settled[i].value){results.push({n:lo+i,url:settled[i].value});found++;}
    }
    if(found===0)keep=false;
    scanStart+=batch;
    if(hi>=maxPage)keep=false;
  }
  if(results.length===0)return firstPath?[firstPath]:[];
  results.sort((a,b)=>a.n-b.n);
  return results.map(r=>r.url);
}
async function probePage(dir,n){
  for(const suffix of ['_c_xfile.jpg','_xfile.jpg']){
    const url=dir+n+suffix;
    try{
      const resp=await fetch(url,{headers:{'Range':'bytes=0-3'}});
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
  readerList.onscroll=()=>{
    if(loadingChapter)return;
    if(readerList.scrollTop+readerList.clientHeight>=readerList.scrollHeight-200){
      const next=chaptersCache[currentChapterIdx+1];
      if(next&&!loadedChapters.find(c=>c.id===next.id))appendNextChapter(next);
    }
    if(readerList.scrollTop<10&&currentChapterIdx>0){
      const prev=chaptersCache[currentChapterIdx-1];
      if(prev&&!loadedChapters.find(c=>c.id===prev.id))prependPrevChapter(prev);
    }
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
    const pages=await getChapterPages(ch);
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
      loadXorImage(url).then(src=>{img.src=src;}).catch(()=>{});
    }
    loadedChapters.push({id:ch.id,name:ch.name,pay:ch.pay,element:chapterDiv});
    readerTitle.textContent=ch.name;
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
    const pages=await getChapterPages(ch);
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
      loadXorImage(url).then(src=>{img.src=src;}).catch(()=>{});
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
  }catch(e){hint.textContent='加载失败';}
  loadingChapter=false;
}
async function getChapterPages(ch){
  await ensureLogin();
  const r=await apiCall('/v2/api/comic/chapter',{mid:currentComic.id,id:ch.id});
  const d=r.data||{};
  let imglist='',domain=d.domain||IMG_CDN,auth=!!(d.data&&d.data.auth);
  if(d.data)imglist=d.data.imglist||'';
  if(!auth&&ch.pay!==0){
    const br=await apiCall('/v2/api/comic/buy',{id:ch.id});
    if(br.code===1&&br.data&&br.data.imglist){imglist=br.data.imglist;auth=true;}
  }
  let pages=parseImgList(imglist,domain);
  if(pages.length<=1&&!auth)pages=await enumeratePages(pages[0]||imglist,domain);
  return pages;
}
$('readerBack').addEventListener('click',()=>showView('mainView'));
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
    const canNative=videoEl.canPlayType('application/vnd.apple.mpegurl');
    if(canNative){
      videoEl.src=m3u8;
      videoEl.play().catch(()=>{});
    }else{
      await ensureHls();
      if(window.Hls&&window.Hls.isSupported()){
        if(videoEl._hls)videoEl._hls.destroy();
        const hls=new window.Hls({maxBufferLength:30,maxMaxBufferLength:60});
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
  if(videoEl._hls){videoEl._hls.destroy();videoEl._hls=null;}
  videoEl.pause();videoEl.src='';
  showView('mainView');
});
/* ===== forum detail ===== */
async function openForum(f){
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
$('forumBack').addEventListener('click',()=>showView('mainView'));
/* ===== view switching ===== */
function showView(id){
  ['mainView','readerView','playerView','forumView'].forEach(v=>{
    $(v).classList.toggle('hidden',v!==id);
  });
  if(id==='mainView')window.scrollTo(0,0);
}
/* ===== init ===== */
if('serviceWorker' in navigator){
  navigator.serviceWorker.register('sw.js').catch(()=>{});
}
switchMode(0);
