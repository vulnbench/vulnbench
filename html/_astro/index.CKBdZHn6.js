globalThis.process??={};globalThis.process.env??={};function m(i,t){if(!i)return;var a=document.createElement("canvas");a.style.cssText="display:block;width:100%;height:100%",i.appendChild(a);var e=a.getContext("webgl2");if(!e){i.style.display="none";return}var g=`#version 300 es
precision mediump float;
layout(location=0) in vec4 a_position;
void main(){gl_Position=a_position;}`,_=`#version 300 es
precision mediump float;
uniform float u_time;uniform vec2 u_resolution;uniform vec4 u_colorFront;uniform float u_shape;uniform float u_pxSize;
out vec4 fragColor;
#define TWO_PI 6.28318530718
float hash11(float p){p=fract(p*0.3183099)+0.1;p*=p+19.19;return fract(p*p);}
vec3 permute(vec3 x){return mod(((x*34.0)+1.0)*x,289.0);}
float snoise(vec2 v){const vec4 C=vec4(0.211324865405187,0.366025403784439,-0.577350269189626,0.024390243902439);vec2 i=floor(v+dot(v,C.yy));vec2 x0=v-i+dot(i,C.xx);vec2 i1=(x0.x>x0.y)?vec2(1.0,0.0):vec2(0.0,1.0);vec4 x12=x0.xyxy+C.xxzz;x12.xy-=i1;i=mod(i,289.0);vec3 p=permute(permute(i.y+vec3(0.0,i1.y,1.0))+i.x+vec3(0.0,i1.x,1.0));vec3 m=max(0.5-vec3(dot(x0,x0),dot(x12.xy,x12.xy),dot(x12.zw,x12.zw)),0.0);m=m*m;m=m*m;vec3 x2=2.0*fract(p*C.www)-1.0;vec3 h=abs(x2)-0.5;vec3 ox=floor(x2+0.5);vec3 a0=x2-ox;m*=1.79284291400159-0.85373472095314*(a0*a0+h*h);vec3 g;g.x=a0.x*x0.x+h.x*x0.y;g.yz=a0.yz*x12.xz+h.yz*x12.yw;return 130.0*dot(m,g);}
float getSimplexNoise(vec2 uv,float t){return .5*snoise(uv-vec2(0.,.3*t))+.5*snoise(2.*uv+vec2(0.,.32*t));}
const int bayer4x4[16]=int[16](0,8,2,10,12,4,14,6,3,11,1,9,15,7,13,5);
float getBayerValue(vec2 uv){ivec2 pos=ivec2(mod(uv,4.0));return float(bayer4x4[pos.y*4+pos.x])/16.0;}
void main(){
  float t=.5*u_time;
  vec2 uv=gl_FragCoord.xy/u_resolution.xy;uv-=.5;
  float pxSize=u_pxSize;
  vec2 pxSizeUv=gl_FragCoord.xy;pxSizeUv-=.5*u_resolution;pxSizeUv/=pxSize;
  vec2 pixelizedUv=floor(pxSizeUv)*pxSize/u_resolution.xy;pixelizedUv+=.5;pixelizedUv-=.5;
  vec2 shape_uv=pixelizedUv;
  float shape=0.0;
  if(u_shape<1.5){
    vec2 simplex_uv=pxSizeUv*.001;
    shape=0.5+0.5*getSimplexNoise(simplex_uv,t);shape=smoothstep(0.3,0.9,shape);
  }else if(u_shape<2.5){
    vec2 warp_uv=pxSizeUv*.006;
    for(float i=1.0;i<8.0;i++){warp_uv.x+=0.3/i*sin(i*2.3*warp_uv.y+t*0.6+i*0.7);warp_uv.y+=0.3/i*cos(i*1.9*warp_uv.x+t*0.4+i*0.5);}
    float v1=sin(warp_uv.x*3.0+warp_uv.y*2.5+t*0.8);float v2=cos(warp_uv.y*3.5-warp_uv.x*2.0-t*0.5);float v3=sin(warp_uv.x*1.5-warp_uv.y*2.8+t*0.3);
    shape=0.5+0.5*sin(v1*2.0+v2*2.0+v3*1.5);shape=pow(shape,1.8);
  }else if(u_shape<3.5){
    shape_uv*=.05;
    float stripeIdx=floor(2.*shape_uv.x/TWO_PI);float rand=hash11(stripeIdx*10.);
    rand=sign(rand-.5)*pow(.1+abs(rand),.4);
    shape=sin(shape_uv.x)*cos(shape_uv.y-5.*rand*t);shape=pow(abs(shape),6.);
  }else if(u_shape<4.5){
    shape_uv*=4.;
    float wave=cos(.5*shape_uv.x-2.*t)*sin(1.5*shape_uv.x+t)*(.75+.25*cos(3.*t));
    shape=1.-smoothstep(-1.,1.,shape_uv.y+wave);
  }else if(u_shape<5.5){
    float dist=length(shape_uv);float waves=sin(pow(dist,1.7)*7.-3.*t)*.5+.5;shape=waves;
  }else if(u_shape<6.5){
    float l=length(shape_uv);float angle=6.*atan(shape_uv.y,shape_uv.x)+4.*t;
    float twist=1.2;float offset=pow(l,-twist)+angle/TWO_PI;
    float mid=smoothstep(0.,1.,pow(l,twist));shape=mix(0.,fract(offset),mid);
  }
  float dithering=getBayerValue(pxSizeUv);dithering-=.5;float res=step(.5,shape+dithering);
  vec3 fg=u_colorFront.rgb*u_colorFront.a;fragColor=vec4(fg*res,u_colorFront.a*res);
}`;function u(n,r){var s=e.createShader(n);return e.shaderSource(s,r),e.compileShader(s),e.getShaderParameter(s,e.COMPILE_STATUS)?s:null}var p=u(e.VERTEX_SHADER,g),c=u(e.FRAGMENT_SHADER,_);if(!p||!c){i.style.display="none";return}var o=e.createProgram();if(e.attachShader(o,p),e.attachShader(o,c),e.linkProgram(o),!e.getProgramParameter(o,e.LINK_STATUS)){i.style.display="none";return}var y=e.createBuffer();e.bindBuffer(e.ARRAY_BUFFER,y),e.bufferData(e.ARRAY_BUFFER,new Float32Array([-1,-1,1,-1,-1,1,-1,1,1,-1,1,1]),e.STATIC_DRAW);var f=e.getAttribLocation(o,"a_position");e.enableVertexAttribArray(f),e.vertexAttribPointer(f,2,e.FLOAT,!1,0,0);var w=e.getUniformLocation(o,"u_time"),S=e.getUniformLocation(o,"u_resolution"),z=e.getUniformLocation(o,"u_colorFront"),E=e.getUniformLocation(o,"u_shape"),A=e.getUniformLocation(o,"u_pxSize"),h=0,d=Date.now(),v=t.speed||1,l=v;t.hoverSpeed&&(i.parentElement?.addEventListener("mouseenter",function(){l=t.hoverSpeed}),i.parentElement?.addEventListener("mouseleave",function(){l=t.speed||1}));function x(){if(t.resWidth&&t.resHeight)a.width=t.resWidth,a.height=t.resHeight;else{var n=i.getBoundingClientRect(),r=Math.min(window.devicePixelRatio||1,2);a.width=n.width*r,a.height=n.height*r}e.viewport(0,0,a.width,a.height)}x(),window.addEventListener("resize",x),(function n(){var r=Date.now(),s=(r-d)*.001;d=r,v+=(l-v)*.05,h+=s*v,e.clear(e.COLOR_BUFFER_BIT),e.useProgram(o),e.uniform1f(w,h),e.uniform2f(S,a.width,a.height),e.uniform4fv(z,t.color),e.uniform1f(E,t.shape),e.uniform1f(A,t.pxSize||4),e.drawArrays(e.TRIANGLES,0,6),requestAnimationFrame(n)})()}(function(){var i=document.getElementById("gs-nav-toggle"),t=document.getElementById("gs-nav-mobile");i&&t&&(i.addEventListener("click",function(){t.classList.toggle("gs-open")}),t.querySelectorAll("a").forEach(function(a){a.addEventListener("click",function(){t.classList.remove("gs-open")})}))})();m(document.getElementById("gs-vb-hero-shader"),{shape:2,color:[1,1,1,1],pxSize:4,speed:1});m(document.getElementById("gs-vb-cta-shader"),{shape:6,color:[1,1,1,1],pxSize:4,speed:.15});
