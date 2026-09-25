"use strict";

const FileGuardEvidence={
VERSION:"1.0.0",

create(source,type,data,options={}){
return{
id:options.id||this.createId(source,type),
source:source||"unknown",
type:type||"unknown",
importance:options.importance||"NORMAL",
description:options.description||"",
data:data===undefined?null:data,
timestamp:Date.now()
};
},

createId(source,type){
const a=String(source||"unknown").replace(/[^a-z0-9]/gi,"").toLowerCase();
const b=String(type||"unknown").replace(/[^a-z0-9]/gi,"").toLowerCase();
return`${a}-${b}-${Date.now()}-${Math.random().toString(36).slice(2,8)}`;
},

fromDetection(detection){
const evidence=[];

if(!detection)return evidence;

if(detection.primary){
evidence.push(this.create(
"detector",
"format",
detection.primary,
{
importance:"HIGH",
description:"Primary file-format detection result."
}
));
}

if(Array.isArray(detection.matches)){
for(const match of detection.matches){
evidence.push(this.create(
"detector",
"signature",
match,
{
importance:"HIGH",
description:"File signature matched a known format."
}
));
}
}

if(Array.isArray(detection.anomalies)){
for(const anomaly of detection.anomalies){
evidence.push(this.create(
"detector",
"anomaly",
anomaly.evidence||anomaly,
{
importance:anomaly.severity==="HIGH"?"HIGH":"NORMAL",
description:anomaly.title||"Detector anomaly."
}
));
}
}

return evidence;
},

fromArchive(archive){
const evidence=[];

if(!archive)return evidence;

if(archive.evidence){
if(Array.isArray(archive.evidence.signatures)){
for(const signature of archive.evidence.signatures){
evidence.push(this.create(
"archive",
"signature",
signature,
{
importance:"HIGH",
description:"Archive signature evidence."
}
));
}
}

if(archive.evidence.centralDirectory){
evidence.push(this.create(
"archive",
"central-directory",
archive.evidence.centralDirectory,
{
importance:"HIGH",
description:"ZIP central-directory structural evidence."
}
));
}

if(Array.isArray(archive.evidence.containerMarkers)&&archive.evidence.containerMarkers.length){
evidence.push(this.create(
"archive",
"container-marker",
archive.evidence.containerMarkers,
{
importance:"HIGH",
description:"Markers used to identify the container type."
}
));
}
}

if(Array.isArray(archive.findings)){
for(const finding of archive.findings){
if(finding.evidence!==null&&finding.evidence!==undefined){
evidence.push(this.create(
"archive",
"finding-evidence",
finding.evidence,
{
id:finding.id+"-evidence",
importance:finding.severity==="HIGH"?"HIGH":"NORMAL",
description:finding.title||"Archive finding evidence."
}
));
}
}
}

return evidence;
},

fromFindings(findings){
const evidence=[];

if(!Array.isArray(findings))return evidence;

for(const finding of findings){
if(!finding||finding.evidence===null||finding.evidence===undefined)continue;

evidence.push(this.create(
finding.source||"unknown",
"finding",
finding.evidence,
{
id:(finding.id||"finding")+"-evidence",
importance:finding.severity==="HIGH"?"HIGH":"NORMAL",
description:finding.title||"Finding evidence."
}
));
}

return evidence;
},

merge(...groups){
const result=[];
const seen=new Set();

for(const group of groups){
if(!Array.isArray(group))continue;

for(const item of group){
if(!item||!item.id)continue;
if(seen.has(item.id))continue;

seen.add(item.id);
result.push(item);
}
}

return result;
},

summarize(evidence){
if(!Array.isArray(evidence)){
return{
total:0,
high:0,
normal:0,
sources:[]
};
}

const sources=new Set();
let high=0;
let normal=0;

for(const item of evidence){
if(item.source)sources.add(item.source);
if(item.importance==="HIGH")high++;
else normal++;
}

return{
total:evidence.length,
high,
normal,
sources:Array.from(sources)
};
},

validate(evidence){
if(!Array.isArray(evidence))return false;

return evidence.every(item=>
item&&
typeof item.id==="string"&&
typeof item.source==="string"&&
typeof item.type==="string"
);
}
};

window.FileGuardEvidence=FileGuardEvidence;
