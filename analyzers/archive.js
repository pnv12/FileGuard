"use strict";

const FileGuardArchiveAnalyzer = {
    VERSION:"2.0.0",
    MAX_ENTRIES:100000,
    SUSPICIOUS_UNCOMPRESSED_SIZE:100*1024*1024,
    SUSPICIOUS_COMPRESSION_RATIO:100,
    ZIP_LOCAL_FILE_HEADER:0x04034B50,
    ZIP_CENTRAL_DIRECTORY_HEADER:0x02014B50,
    ZIP_END_OF_CENTRAL_DIRECTORY:0x06054B50,
    ZIP64_END_OF_CENTRAL_DIRECTORY:0x06064B50,
    ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR:0x07064B50,

    async analyze(file){
        this.validateFile(file);
        const startedAt=performance.now();
        const result={
            analyzer:"archive",
            analyzerVersion:this.VERSION,
            status:"unknown",
            format:"ZIP",
            containerType:"ZIP",
            entryCount:0,
            entries:[],
            statistics:{
                compressedBytes:0,
                uncompressedBytes:0,
                compressionRatio:null,
                encryptedEntries:0,
                directories:0,
                files:0
            },
            features:{
                zip64:false,
                encrypted:false,
                duplicateNames:false,
                pathTraversal:false,
                absolutePaths:false,
                suspiciousCompression:false,
                nestedArchives:false
            },
            findings:[],
            evidence:{
                signatures:[],
                containerMarkers:[],
                centralDirectory:null
            }
        };

        const buffer=await file.arrayBuffer();
        const bytes=new Uint8Array(buffer);
        const signature=bytes.length>=4?this.readUInt32LE(bytes,0):null;

        if(signature!==null){
            result.evidence.signatures.push(
                "0x"+signature.toString(16).padStart(8,"0")
            );
        }

        const endRecord=this.findEndOfCentralDirectory(bytes);

        if(!endRecord){
            result.status="invalid";
            result.findings.push({
                id:"invalid-zip-structure",
                severity:"MEDIUM",
                confidence:"HIGH",
                title:"ZIP end-of-central-directory record was not found.",
                description:"The file has ZIP-like characteristics but its central directory could not be located.",
                evidence:null,
                recommendation:"Treat the container as structurally invalid until further inspection."
            });
            result.durationMs=Math.round(performance.now()-startedAt);
            return result;
        }

        result.evidence.centralDirectory={
            offset:endRecord.offset,
            entries:endRecord.entries,
            centralDirectoryOffset:endRecord.centralDirectoryOffset,
            centralDirectorySize:endRecord.centralDirectorySize
        };

        const zip64=this.detectZip64(bytes,endRecord);
        result.features.zip64=zip64.detected;

        if(zip64.detected){
            result.findings.push({
                id:"zip64-container",
                severity:"INFO",
                confidence:"HIGH",
                title:"ZIP64 structures detected.",
                description:"The archive uses ZIP64 extensions for large archive metadata.",
                evidence:zip64.evidence,
                recommendation:"Use ZIP64-aware parsers when processing this container."
            });
        }

        const parsed=this.parseCentralDirectory(bytes,endRecord);

        if(parsed.error){
            result.status="invalid";
            result.entries=parsed.entries;
            result.entryCount=parsed.entries.length;
            result.findings.push({
                id:"central-directory-parse-failed",
                severity:"MEDIUM",
                confidence:"HIGH",
                title:"ZIP central directory could not be parsed completely.",
                description:parsed.error,
                evidence:{
                    centralDirectoryOffset:endRecord.centralDirectoryOffset,
                    centralDirectorySize:endRecord.centralDirectorySize,
                    parsedEntries:parsed.entries.length
                },
                recommendation:"Treat the archive as structurally suspicious until it can be validated by another ZIP parser."
            });
            result.durationMs=Math.round(performance.now()-startedAt);
            return result;
        }

        result.entries=parsed.entries;
        result.entryCount=parsed.entries.length;

        if(parsed.entries.length>this.MAX_ENTRIES){
            result.findings.push({
                id:"entry-count-limit",
                severity:"MEDIUM",
                confidence:"HIGH",
                title:"Archive contains an unusually large number of entries.",
                description:`The archive contains ${parsed.entries.length.toLocaleString()} entries.`,
                evidence:{
                    entryCount:parsed.entries.length,
                    limit:this.MAX_ENTRIES
                },
                recommendation:"Avoid blindly extracting the archive. Inspect the entry list before processing it."
            });
        }

        this.analyzeEntries(result);

        const container=this.identifyContainer(result.entries);
        result.containerType=container.type;
        result.format=container.format;
        result.evidence.containerMarkers=container.markers;

        if(container.type!=="ZIP"){
            result.findings.push({
                id:`container-${container.type.toLowerCase()}`,
                severity:"INFO",
                confidence:"HIGH",
                title:`${container.type} container identified.`,
                description:container.description,
                evidence:{markers:container.markers},
                recommendation:"Route the container to its specialized analyzer when available."
            });
        }

        const nested=this.detectNestedArchives(result.entries);

        if(nested.length>0){
            result.features.nestedArchives=true;
            result.findings.push({
                id:"nested-archives",
                severity:"LOW",
                confidence:"HIGH",
                title:"Nested archive files detected.",
                description:"The container contains one or more archive-like files.",
                evidence:{entries:nested},
                recommendation:"Inspect nested archives separately if their contents are relevant to the investigation."
            });
        }

        result.status="completed";
        result.durationMs=Math.round(performance.now()-startedAt);
        return result;
    },

    findEndOfCentralDirectory(bytes){
        const minimumOffset=Math.max(0,bytes.length-0xFFFF-22);

        for(let offset=bytes.length-22;offset>=minimumOffset;offset--){
            if(this.readUInt32LE(bytes,offset)!==this.ZIP_END_OF_CENTRAL_DIRECTORY)continue;
            if(offset+22>bytes.length)continue;

            const diskNumber=this.readUInt16LE(bytes,offset+4);
            const centralDirectoryDisk=this.readUInt16LE(bytes,offset+6);
            const entriesOnDisk=this.readUInt16LE(bytes,offset+8);
            const totalEntries=this.readUInt16LE(bytes,offset+10);
            const centralDirectorySize=this.readUInt32LE(bytes,offset+12);
            const centralDirectoryOffset=this.readUInt32LE(bytes,offset+16);
            const commentLength=this.readUInt16LE(bytes,offset+20);

            if(offset+22+commentLength>bytes.length)continue;

            return{
                offset,
                diskNumber,
                centralDirectoryDisk,
                entriesOnDisk,
                entries:totalEntries,
                centralDirectorySize,
                centralDirectoryOffset
            };
        }

        return null;
    },

    detectZip64(bytes,endRecord){
        const evidence=[];

        if(
            endRecord.entries===0xFFFF||
            endRecord.centralDirectorySize===0xFFFFFFFF||
            endRecord.centralDirectoryOffset===0xFFFFFFFF
        ){
            evidence.push("ZIP64 marker values present in EOCD.");
        }

        const start=Math.max(0,endRecord.offset-256);

        for(let offset=endRecord.offset-20;offset>=start;offset--){
            if(this.readUInt32LE(bytes,offset)===this.ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR){
                evidence.push("ZIP64 EOCD locator detected.");
                break;
            }
        }

        for(let offset=endRecord.offset-56;offset>=start;offset--){
            if(this.readUInt32LE(bytes,offset)===this.ZIP64_END_OF_CENTRAL_DIRECTORY){
                evidence.push("ZIP64 EOCD record detected.");
                break;
            }
        }

        return{
            detected:evidence.length>0,
            evidence
        };
    },

    parseCentralDirectory(bytes,endRecord){
        const entries=[];
        let offset=endRecord.centralDirectoryOffset;
        const declaredEnd=
            endRecord.centralDirectoryOffset+
            endRecord.centralDirectorySize;

        if(endRecord.centralDirectoryOffset>bytes.length){
            return{
                error:"The declared central directory offset is outside the file.",
                entries
            };
        }

        if(declaredEnd>bytes.length){
            return{
                error:"The declared central directory extends beyond the file.",
                entries
            };
        }

        const endOffset=declaredEnd;

        while(offset+46<=endOffset){
            if(
                this.readUInt32LE(bytes,offset)!==
                this.ZIP_CENTRAL_DIRECTORY_HEADER
            ){
                return{
                    error:"Unexpected data was found where a central directory entry was expected.",
                    entries
                };
            }

            const versionMadeBy=this.readUInt16LE(bytes,offset+4);
            const versionNeeded=this.readUInt16LE(bytes,offset+6);
            const flags=this.readUInt16LE(bytes,offset+8);
            const compressionMethod=this.readUInt16LE(bytes,offset+10);
            const modifiedTime=this.readUInt16LE(bytes,offset+12);
            const modifiedDate=this.readUInt16LE(bytes,offset+14);
            const crc32=this.readUInt32LE(bytes,offset+16);
            const compressedSize=this.readUInt32LE(bytes,offset+20);
            const uncompressedSize=this.readUInt32LE(bytes,offset+24);
            const fileNameLength=this.readUInt16LE(bytes,offset+28);
            const extraLength=this.readUInt16LE(bytes,offset+30);
            const commentLength=this.readUInt16LE(bytes,offset+32);
            const diskStart=this.readUInt16LE(bytes,offset+34);
            const internalAttributes=this.readUInt16LE(bytes,offset+36);
            const externalAttributes=this.readUInt32LE(bytes,offset+38);
            const localHeaderOffset=this.readUInt32LE(bytes,offset+42);

            const totalHeaderSize=
                46+
                fileNameLength+
                extraLength+
                commentLength;

            if(offset+totalHeaderSize>endOffset){
                return{
                    error:"A central directory entry extends beyond the declared central directory bounds.",
                    entries
                };
            }

            const fileNameBytes=bytes.slice(
                offset+46,
                offset+46+fileNameLength
            );

            const extraBytes=bytes.slice(
                offset+46+fileNameLength,
                offset+46+fileNameLength+extraLength
            );

            const commentBytes=bytes.slice(
                offset+46+fileNameLength+extraLength,
                offset+totalHeaderSize
            );

            const fileName=this.decodeFileName(
                fileNameBytes,
                flags
            );

            const comment=this.decodeText(commentBytes);
            const extraFields=this.parseExtraFields(extraBytes);
            const directory=fileName.endsWith("/");
            const encrypted=Boolean(flags&0x0001);

            entries.push({
                name:fileName,
                type:directory?"directory":"file",
                compressedSize,
                uncompressedSize,
                compressionMethod,
                compression:this.getCompressionName(compressionMethod),
                crc32:"0x"+crc32.toString(16).padStart(8,"0"),
                flags,
                encrypted,
                versionMadeBy,
                versionNeeded,
                modifiedTime,
                modifiedDate,
                diskStart,
                internalAttributes,
                externalAttributes,
                localHeaderOffset,
                comment,
                extraFields,
                zip64:
                    compressedSize===0xFFFFFFFF||
                    uncompressedSize===0xFFFFFFFF||
                    localHeaderOffset===0xFFFFFFFF||
                    diskStart===0xFFFF,
                path:{
                    traversal:this.hasPathTraversal(fileName),
                    absolute:this.isAbsolutePath(fileName)
                }
            });

            offset+=totalHeaderSize;
        }

        if(offset!==endOffset){
            return{
                error:"The central directory contains trailing or unparsed bytes.",
                entries
            };
        }

        return{entries};
    },

    parseExtraFields(bytes){
        const fields=[];
        let offset=0;

        while(offset+4<=bytes.length){
            const id=this.readUInt16LE(bytes,offset);
            const size=this.readUInt16LE(bytes,offset+2);
            const start=offset+4;
            const end=start+size;

            if(end>bytes.length)break;

            fields.push({
                id:"0x"+id.toString(16).padStart(4,"0"),
                size
            });

            offset=end;
        }

        return fields;
    },

    analyzeEntries(result){
        const entries=result.entries;
        const names=new Set();

        let duplicateNames=0;
        let compressedBytes=0;
        let uncompressedBytes=0;
        let encryptedEntries=0;
        let directories=0;
        let files=0;
        let traversal=[];
        let absolute=[];
        let suspicious=[];

        for(const entry of entries){
            if(names.has(entry.name)){
                duplicateNames++;
            }else{
                names.add(entry.name);
            }

            if(entry.type==="directory"){
                directories++;
            }else{
                files++;
            }

            compressedBytes+=entry.compressedSize;
            uncompressedBytes+=entry.uncompressedSize;

            if(entry.encrypted)encryptedEntries++;
            if(entry.path.traversal)traversal.push(entry.name);
            if(entry.path.absolute)absolute.push(entry.name);

            if(
                entry.type!=="directory"&&
                entry.compressedSize>0&&
                entry.uncompressedSize>=this.SUSPICIOUS_UNCOMPRESSED_SIZE
            ){
                const ratio=
                    entry.uncompressedSize/
                    entry.compressedSize;

                if(ratio>=this.SUSPICIOUS_COMPRESSION_RATIO){
                    suspicious.push({
                        name:entry.name,
                        compressedSize:entry.compressedSize,
                        uncompressedSize:entry.uncompressedSize,
                        ratio
                    });
                }
            }
        }

        result.statistics.compressedBytes=compressedBytes;
        result.statistics.uncompressedBytes=uncompressedBytes;
        result.statistics.encryptedEntries=encryptedEntries;
        result.statistics.directories=directories;
        result.statistics.files=files;
        result.statistics.compressionRatio=
            compressedBytes>0?
            uncompressedBytes/compressedBytes:
            null;

        if(duplicateNames>0){
            result.features.duplicateNames=true;
            result.findings.push({
                id:"duplicate-entry-names",
                severity:"MEDIUM",
                confidence:"HIGH",
                title:"Duplicate archive entry names detected.",
                description:`${duplicateNames} duplicate entry name(s) were found.`,
                evidence:{duplicateCount:duplicateNames},
                recommendation:"Inspect duplicate entries because different extraction tools may handle them differently."
            });
        }

        if(encryptedEntries>0){
            result.features.encrypted=true;
            result.findings.push({
                id:"encrypted-entries",
                severity:"INFO",
                confidence:"HIGH",
                title:"Encrypted archive entries detected.",
                description:`${encryptedEntries} archive entry or entries use ZIP encryption.`,
                evidence:{encryptedEntries},
                recommendation:"Encrypted content cannot be fully inspected without the required credentials."
            });
        }

        if(traversal.length>0){
            result.features.pathTraversal=true;
            result.findings.push({
                id:"path-traversal",
                severity:"HIGH",
                confidence:"HIGH",
                title:"Path traversal entry detected.",
                description:"One or more archive entries contain path traversal components such as ../.",
                evidence:{entries:traversal.slice(0,50)},
                recommendation:"Do not extract the archive blindly. Normalize and validate every destination path."
            });
        }

        if(absolute.length>0){
            result.features.absolutePaths=true;
            result.findings.push({
                id:"absolute-paths",
                severity:"MEDIUM",
                confidence:"HIGH",
                title:"Absolute archive paths detected.",
                description:"One or more entries use an absolute filesystem path.",
                evidence:{entries:absolute.slice(0,50)},
                recommendation:"Do not use archive entry paths directly as filesystem destinations."
            });
        }

        if(suspicious.length>0){
            result.features.suspiciousCompression=true;
            result.findings.push({
                id:"suspicious-compression-ratio",
                severity:"LOW",
                confidence:"MEDIUM",
                title:"Very high compression ratio detected.",
                description:`${suspicious.length} file(s) have a very high declared compression ratio.`,
                evidence:{
                    threshold:this.SUSPICIOUS_COMPRESSION_RATIO,
                    minimumUncompressedSize:this.SUSPICIOUS_UNCOMPRESSED_SIZE,
                    entries:suspicious.slice(0,50)
                },
                recommendation:"Inspect unusually compressed content before automatic extraction."
            });
        }
    },

    identifyContainer(entries){
        const names=new Set(entries.map(entry=>entry.name));
        let markers=[];

        const hasManifest=names.has("AndroidManifest.xml");
        const hasDex=Array.from(names).some(
            name=>/^classes(?:\d+)?\.dex$/i.test(name)
        );

        if(hasManifest&&hasDex){
            markers=["AndroidManifest.xml","classes*.dex"];
            return{
                type:"APK",
                format:"Android Package",
                description:"The ZIP container contains structural markers characteristic of an Android application package.",
                markers
            };
        }

        if(names.has("META-INF/MANIFEST.MF")){
            markers=["META-INF/MANIFEST.MF"];
            return{
                type:"JAR",
                format:"Java Archive",
                description:"The ZIP container contains the standard JAR manifest 
