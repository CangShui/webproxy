package main

import (
	"net/url"
	"strconv"
	"strings"
)

// urlParamsToRewrite are query parameter names whose value is a URL that
// should be rewritten when it points at a proxied host. This keeps OAuth-style
// callbacks (redirect_uri etc.) on the proxy domain.
var urlParamsToRewrite = map[string]bool{
	"redirect_uri":             true,
	"redirect":                 true,
	"return_to":                true,
	"return":                   true,
	"next":                     true,
	"continue":                 true,
	"continue_url":             true,
	"callback":                 true,
	"callback_url":             true,
	"callbackurl":              true,
	"cancel_url":               true,
	"success_url":              true,
	"post_logout_redirect_uri": true,
	"logout_uri":               true,
	"login_uri":                true,
	"signup_uri":               true,
	"forward":                  true,
	"goto":                     true,
	"destination":              true,
	"url":                      true,
	"link":                     true,
	"target":                   true,
	"image":                    true,
	"img":                      true,
	"src":                      true,
	"popup_url":                true,
}

// rewriteURLParams rewrites URL-valued query parameters that point at proxied
// hosts so redirect/callback flows stay on the proxy domain.
func (p *Proxy) rewriteURLParams(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.RawQuery == "" {
		return raw
	}
	q := u.Query()
	changed := false
	for k := range q {
		lk := strings.ToLower(k)
		base := strings.TrimSuffix(lk, "[]")
		if !urlParamsToRewrite[base] && !urlParamsToRewrite[lk] {
			continue
		}
		vals := q[k]
		for i, v := range vals {
			if nv := p.rewriteAbsParam(v); nv != v {
				vals[i] = nv
				changed = true
			}
		}
	}
	if !changed {
		return raw
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// rewriteAbsParam rewrites v only when it is an absolute URL (http/https or
// protocol-relative) pointing at a proxied host, leaving relative values alone.
func (p *Proxy) rewriteAbsParam(v string) string {
	u, err := url.Parse(strings.TrimSpace(v))
	if err != nil {
		return v
	}
	absolute := u.Scheme == "http" || u.Scheme == "https" || (u.Scheme == "" && strings.HasPrefix(v, "//"))
	if !absolute || !p.shouldProxyHost(u.Host) {
		return v
	}
	return p.rewriteURL(v)
}

// runtimeShimScript returns a small script that rewrites JS-driven
// navigations, window.open, fetch and XHR calls at runtime so URLs pointing at
// proxied hosts (and URL-valued query params like redirect_uri) stay on the
// proxy domain even when the site constructs them dynamically.
func (p *Proxy) runtimeShimScript() string {
	hosts := []string{p.targetHostname}
	if p.registrable != "" && p.registrable != p.targetHostname {
		hosts = append(hosts, p.registrable)
	}
	hosts = append(hosts, p.extraDomains...)
	seen := map[string]bool{}
	var uniq []string
	for _, h := range hosts {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		uniq = append(uniq, h)
	}
	direct := make([]string, 0, len(p.directDomains))
	for _, d := range p.directDomains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d != "" {
			direct = append(direct, d)
		}
	}
	js := shimTemplate
	js = strings.ReplaceAll(js, "OWN_PLACEHOLDER", strconv.Quote(p.ownOrigin))
	js = strings.ReplaceAll(js, "HOSTS_PLACEHOLDER", jsArray(uniq))
	js = strings.ReplaceAll(js, "DIRECT_PLACEHOLDER", jsArray(direct))
	return js
}

func jsArray(ss []string) string {
	var b strings.Builder
	b.WriteByte('[')
	for i, s := range ss {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(strconv.Quote(s))
	}
	b.WriteByte(']')
	return b.String()
}

const shimTemplate = `(function(){
var OWN=OWN_PLACEHOLDER;
var HOSTS=HOSTS_PLACEHOLDER;
var DIRECT=DIRECT_PLACEHOLDER;
var PARAMS=["redirect_uri","redirect","return_to","return","next","continue","continue_url","callback","callback_url","callbackurl","cancel_url","success_url","post_logout_redirect_uri","logout_uri","login_uri","signup_uri","forward","goto","destination","url","link","target","image","img","src","popup_url"];
function isDirect(h){h=String(h||"").toLowerCase();for(var j=0;j<DIRECT.length;j++){var d=DIRECT[j];if(h===d||(h.length>d.length&&h.charAt(h.length-d.length-1)==="."&&h.slice(-d.length)===d))return true;}return false;}
function isKnown(h){h=String(h||"").toLowerCase();var i=h.indexOf(":");if(i>0)h=h.slice(0,i);for(var j=0;j<HOSTS.length;j++){var d=HOSTS[j];if(h===d||(h.length>d.length&&h.charAt(h.length-d.length-1)==="."&&h.slice(-d.length)===d))return true;}return false;}
function isHostLike(h){h=String(h||"").toLowerCase();if(!h)return false;var i=h.lastIndexOf(":");if(i>0){var port=h.slice(i+1);if(!/^\d+$/.test(port))return false;h=h.slice(0,i);}if(!h||h.charAt(0)==="."||h.charAt(h.length-1)==="."||h.charAt(0)==="-"||h.charAt(h.length-1)==="-")return false;if(h.indexOf(".")<0)return false;if(!/^[a-z0-9.\-]+$/.test(h))return false;var last=h.slice(h.lastIndexOf(".")+1);if(last.length<2||last.length>24)return false;if(!/^[a-z]+$/.test(last))return false;if(/^(a?png|aspx?|avif|bmp|cgi|cfm|css|csv|do|docx?|eot|gif|gz|htm[l]?|ico|jpe?g|jsp|js|json|map|md|mjs|cjs|mov|mp3|mp4|otf|pdf|php|pl|png|ppt[x]?|py|rar|rss|shtml|svg|tar|tex|ts|ttf|txt|wav|wasm|webmanifest|webm|webp|woff2?|xlsx?|xml|zip)$/.test(last))return false;return true;}
function isHostPrefix(h){return isKnown(h)||isHostLike(h);}
function isPageHost(h){return isHostPrefix(h)&&!isDirect(h)&&h!==ownHost();}
function isProxy(h){h=String(h||"").toLowerCase();var i=h.indexOf(":");if(i>0)h=h.slice(0,i);if(!h||h===ownHost())return false;if(isDirect(h))return false;return true;}
function base(){return document.baseURI||location.href;}
function rewriteParams(u){try{var a=new URL(u,base());if(!a.search)return u;var q=a.search.slice(1).split("&");var changed=false;for(var i=0;i<q.length;i++){var kv=q[i].split("=");if(kv.length<2)continue;var name;try{name=decodeURIComponent(kv[0].replace(/\+/g," ")).toLowerCase().replace(/\[\]$/,"");}catch(e){continue;}if(PARAMS.indexOf(name)<0)continue;var val;try{val=decodeURIComponent(kv.slice(1).join("=").replace(/\+/g," "));}catch(e){continue;}var nv=proxify(val);if(nv!==val){kv[1]=encodeURIComponent(nv);q[i]=kv.join("=");changed=true;}}if(changed){a.search=q.join("&");return a.href;}return u;}catch(e){return u;}}
function ownHost(){try{return new URL(OWN).hostname;}catch(e){return "";}}
var PAGE_HOST="";
try{var _be=document.querySelector("base");var _b=_be&&_be.href?_be.href:(document.baseURI||location.href);var _u=new URL(_b);if(_u.hostname===ownHost()){var _pth=_u.pathname||"";if(_pth.charAt(0)==="/"){var _i2=_pth.indexOf("/",1);var _h2=_i2<0?_pth.slice(1):_pth.slice(1,_i2);if(isPageHost(_h2))PAGE_HOST=_h2;}}}catch(e){}
function pageHost(){try{var p=location.pathname;if(!p||p.charAt(0)!=="/")return PAGE_HOST;var i=p.indexOf("/",1);var h=i<0?p.slice(1):p.slice(1,i);return isPageHost(h)?h:PAGE_HOST;}catch(e){return PAGE_HOST;}}
function proxify(u){if(typeof u!=="string"||u==="")return u;try{var a=new URL(u,base());if(a.protocol!=="http:"&&a.protocol!=="https:")return u;if(isProxy(a.hostname)){return rewriteParams(OWN+"/"+a.host+a.pathname+a.search+a.hash);}var oh=ownHost();if(oh&&a.hostname===oh){var pth=a.pathname||"";if(pth.indexOf("/backend-api/sentinel/")===0){return rewriteParams(u);}var ph=pageHost();if(ph){var seg=a.pathname.indexOf("/",1);var first=seg<0?a.pathname.slice(1):a.pathname.slice(1,seg);if(first!==""&&!isPageHost(first)){return rewriteParams(OWN+"/"+ph+a.pathname+a.search+a.hash);}}return rewriteParams(u);}return rewriteParams(u);}catch(e){return u;}}
try{var L=window.Location&&window.Location.prototype;if(L){var hd=Object.getOwnPropertyDescriptor(L,"href");if(hd&&hd.set){Object.defineProperty(L,"href",{get:hd.get,set:function(v){hd.set.call(this,proxify(v));},configurable:true});}}}catch(e){}
try{var ow=window.open;window.open=function(){var u=arguments[0];if(typeof u==="string"){var p=proxify(u);var args=Array.prototype.slice.call(arguments);args[0]=p;return ow.apply(window,args);}return ow.apply(window,arguments);};}catch(e){}
try{var la=window.location.assign?window.location.assign.bind(window.location):null;if(la){window.location.assign=function(u){return la(proxify(u));};}}catch(e){}
try{var lr=window.location.replace?window.location.replace.bind(window.location):null;if(lr){window.location.replace=function(u){return lr(proxify(u));};}}catch(e){}
try{var of=window.fetch;window.fetch=function(input,init){if(typeof input==="string"){return of.call(window,proxify(input),init);}if(input&&input.url&&typeof input.url==="string"){var p=proxify(input.url);if(p!==input.url){return of.call(window,new Request(p,input),init);}}return of.call(window,input,init);};}catch(e){}
try{var xo=XMLHttpRequest.prototype.open;XMLHttpRequest.prototype.open=function(){var a=Array.prototype.slice.call(arguments);if(a.length>1&&typeof a[1]==="string"){a[1]=proxify(a[1]);}return xo.apply(this,a);};}catch(e){}
try{var ap=HTMLAnchorElement.prototype;var ahd=Object.getOwnPropertyDescriptor(ap,"href");if(ahd&&ahd.set){Object.defineProperty(ap,"href",{get:ahd.get,set:function(v){ahd.set.call(this,proxify(v));},configurable:true});}}catch(e){}
try{var ip=HTMLIFrameElement.prototype;var isd=Object.getOwnPropertyDescriptor(ip,"src");if(isd&&isd.set){Object.defineProperty(ip,"src",{get:isd.get,set:function(v){isd.set.call(this,proxify(v));},configurable:true});}}catch(e){}
try{var sp=HTMLScriptElement.prototype;var ssd=Object.getOwnPropertyDescriptor(sp,"src");if(ssd&&ssd.set){Object.defineProperty(sp,"src",{get:ssd.get,set:function(v){ssd.set.call(this,proxify(v));},configurable:true});}}catch(e){}
function rewriteForm(f){try{if(!f||!f.elements)return;var act=f.getAttribute("action");if(act&&!f.hasAttribute("data-discover")){var pa=proxify(act);if(pa!==act)f.setAttribute("action",pa);}var els=f.elements;for(var i=0;i<els.length;i++){var el=els[i];if(!el||!el.name)continue;var nm=String(el.name).toLowerCase().replace(/\[\]$/,"");if(PARAMS.indexOf(nm)<0)continue;var t=(el.type||"").toLowerCase();if(t==="hidden"||t==="text"||t==="search"||t==="email"||t==="url"){if(typeof el.value==="string"){var nv=proxify(el.value);if(nv!==el.value)el.value=nv;}}}}catch(e){}}
try{var fsp=HTMLFormElement.prototype;var os=fsp.submit;fsp.submit=function(){rewriteForm(this);return os.call(this);};}catch(e){}
document.addEventListener("submit",function(e){try{rewriteForm(e.target);}catch(err){}},true);
function hostPrefix(p){try{var a=new URL(p,base());if(a.hostname!==ownHost())return "";var pth=a.pathname||"";if(pth.charAt(0)!=="/")return "";var i=pth.indexOf("/",1);var f=i<0?pth.slice(1):pth.slice(1,i);return isPageHost(f)?f:"";}catch(e){return "";}}
function crossHostNav(p){var cur=pageHost();var tgt=hostPrefix(p);return tgt!==""&&tgt!==cur;}
try{var h=window.history;var hps=h.pushState;var hrs=h.replaceState;if(hps){h.pushState=function(s,t,u){if(typeof u==="string"){var p=proxify(u);if(crossHostNav(p)){window.location.href=p;return;}if(p!==u)arguments[2]=p;}return hps.apply(this,arguments);};}if(hrs){h.replaceState=function(s,t,u){if(typeof u==="string"){var p=proxify(u);if(crossHostNav(p)){window.location.href=p;return;}if(p!==u)arguments[2]=p;}return hrs.apply(this,arguments);};}}catch(e){}
document.addEventListener("click",function(e){try{var t=e.target;var a=t&&t.closest?t.closest("a[href]"):null;if(!a)return;var h=a.getAttribute("href");if(!h)return;var p=proxify(h);if(p===h)return;e.preventDefault();if(a.target==="_blank"){window.open(p);}else{window.location.href=p;}}catch(err){}},true);
})();`
