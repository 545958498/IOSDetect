/*
 模拟 IOS 对 APP 代码和资源校验的流程，判断资源和代码是否有篡改。
 仅限越狱环境而且没有重打包
 ************ 耗时较长 **************
 */
JValue chkget_patchInfo() BOLLVM
{
    static JValue patches;
    static dispatch_once_t onceToken;
    
    dispatch_once(&onceToken, ^{
        
        if((isJailBreak()))
        {
            // 重打包单独检测，确定是 Apple 的签名， 并且 设备 越狱 或者 越狱过
            /*
             *************** TODO 校验 CDhash 是否 能用公钥验证通过 **************
             1、校验CDhash 与 实际 CodeDirectory 是否符合
             2、校验CodeDirectory 与 实际的代码段是否符合
             3、校验CodeDirectory 与 Info.plist 文件hash值符合
             4、校验CodeDirectory 与 CodeResources 文件hash值符合
             5、校验CodeResources 与 各个资源文件hash值符合
             */
            //_CodeSignature/CodeResources
            
            CHKMacho* main = getMainMacho();
            
            antisdk::JValue CodeResources;
            
            const char* sha1 = OBF("sha1");
            const char* sha256 = OBF("sha256");
            
            const char*CodeResourcesPath = stringEncodeBase64(OBF("GxX0NvZGVTaWduYXR1cmUvQ29kZVJlc291cmNlcw=="));
            char* path = (char*)malloc(safe_strlen(main->pathName) + 256);
            
            // 检测资源，耗时太长，线上观察数据并没有篡改资源的行为，注释掉，不检测
//            if(pathGetInnerFilePath(path, main->pathName, CodeResourcesPath))
//            {
//                JValue filesHashInfo;
//                CodeResources.readPListFile(path);
//                const char* files = OBF("files");
//                const char* files2 = OBF("files2");
//
//                if(CodeResources.has(files))
//                {
//                    filesHashInfo = CodeResources[files];
//                }
//                else if(CodeResources.has(files2))
//                {
//                    filesHashInfo = CodeResources[files2];
//                }
//
//                const char* resourceD = OBF("CodeResourcesCheck: ");
//                // 优先使用files中的hash sha1 计算
//                vector<string> arrKeys;
//
//                filesHashInfo.keys(arrKeys);
//
//                for(size_t i = 0; i < arrKeys.size(); ++ i)
//                {
//                    const char* fileName = arrKeys[i].c_str();
//
//                    JValue hashInfo = filesHashInfo.at(fileName);
//                    // dict 为 files2 包含 hash 和 hash2 ，否则 只有一个 <data></data> 为 hash sha1
//                    bool mustHashSha256 = false;
//                    string fileHash;
//                    if(hashInfo.isObject())
//                    {
//                        if(hashInfo.has("hash"))
//                        {
//                            fileHash = hashInfo.at("hash").asData();
//                        }
//                        else if(hashInfo.has("hash2"))
//                        {
//                            fileHash = hashInfo.at("hash2").asData();
//                            mustHashSha256 = true;
//                        }
//                    }
//                    else
//                    {
//                        fileHash = hashInfo.asData();
//                    }
//
//                    // 对比 hash
//                    if(pathGetInnerFilePath(path, main->pathName, fileName))
//                    {
//                        const char* hash = chkshaOfPathToBase64(path, mustHashSha256?sha256:sha1);
//                        if(!stringEqual(hash, fileHash.c_str()))
//                        {
//                            ANTILOG("file = %s ,hash = %s, filehash = %s",fileName, hash, fileHash.c_str());
//                            if(!stringEqual(fileName, OBF("SC_Info/Manifest.plist")) && !stringEqual(hash, "nil"))  //误报
//                            {
//                                patches["resource"].push_back(stringAppendString(resourceD, fileName));
//                            }
//
//                        }
//                    }
//                }
//
//                CodeResources.clear();
//
//            }
            // 检测 CodeDirectory 内容 是否符合
            CS_CodeDirectory* codeDirectory = main->getCodeDirectory(main)?:main->getCodeDirectory256(main);
            
            if(codeDirectory != NULL)
            {
                // specialSlot 特殊slot的数量 包含 CodeResources、 info.plist 的哈希值
                // hashSize  哈希值的长度， sha1 -> 20字节 sha256 -> 32字节
                // hashtype 哈希类型  sha1 - > 1 , sha256 -> 2
                // pageSize 对主文件每页求哈希时， 每页的大小， 为 (2 ^ pageSize)
                // ncodeSlots 主文件 slot 个数
                // 主文件加载进内存后，数据会改变，不能直接在内存中计算，可以直接计算主文件， 或者只在内存中计算代码段区域
                
               const char* mode = codeDirectory->hashType == 1? sha1 : sha256;
               size_t hashSize = codeDirectory->hashSize;
                
                unsigned char pageHash[hashSize];
                
                if(BE(codeDirectory->nSpecialSlots) >= 5)
                {
                    // -1 Info.plist文件  -3 CodeResources文件 ，暂时只计算这两个
                    if((codeDirectory->hashType == 1 && codeDirectory->hashSize == 20) || (codeDirectory->hashType == 2 && codeDirectory->hashSize == 32))
                    {
                        unsigned char* CodeResourcesSHA = (unsigned char*)((uint8_t*)codeDirectory + BE(codeDirectory->hashOffset) - codeDirectory->hashSize * 3);
                        const char* base64_CodeResourcesSHA = base64_encode(CodeResourcesSHA, codeDirectory->hashSize);
                        if(pathGetInnerFilePath(path, main->pathName, CodeResourcesPath))
                        {
                            const char* fileHash = chkshaOfPathToBase64(path, mode);
                            if(!stringEqual(base64_CodeResourcesSHA, fileHash))
                            {
                                patches["resource"].push_back(stringAppendString(OBF("SlotCheck: "), CodeResourcesPath));
                            }
                        }
                        
                        uint8_t* plistSHA = (uint8_t*)((uint8_t*)codeDirectory + BE(codeDirectory->hashOffset) - codeDirectory->hashSize);
                        const char* base64_plist = base64_encode(plistSHA, codeDirectory->hashSize);
                        if(pathGetInnerFilePath(path, main->pathName, OBF("Info.plist")))
                        {
                            const char* fileHash = chkshaOfPathToBase64(path, mode);
                            if(!stringEqual(base64_plist, fileHash))
                            {
                                patches["resource"].push_back(OBF("SlotCheck: Info.plist"));
                            }
                        }
                        
                        //计算 内嵌 entitlement 的 hash 值
                        if(main->entitleBase != NULL && main->inSpace(main, (uintptr_t)main->entitleBase))
                        {
                            unsigned char* entitlementSHA = (unsigned char*)((uint8_t*)codeDirectory + BE(codeDirectory->hashOffset) - codeDirectory->hashSize * 5);
                            
                            chkshaOfData((unsigned char *)main->entitleBase, BE(main->entitleBase->length), mode, pageHash);
                            
                            if(!memoryEqual(entitlementSHA, pageHash, hashSize))
                            {
                                patches[OBF("entitle")].push_back(OBF("SlotCheck: entitlement"));
                            }
                        }
                    }
                }
                
                /*
                 计算代码段 HASH command_text->vmaddr 开始的地址 按照
                 */
               
                if(main->inSpace(main, (uintptr_t)(void*)main->command_text))
                {
                    uintptr_t start = main->command_text->vmaddr + main->slide;
                    uintptr_t pageSize = (1 << (codeDirectory->pageSize));
            
                    for(uint32_t i = 0; i < BE(codeDirectory->nCodeSlots) - 1; ++i)  // 过滤掉最后一个code slot,只计算 TEXT段一般用不到
                    {
                        uintptr_t hash_start = (start + pageSize * i);
                        if(hash_start < start + main->command_text->vmsize && hash_start- start < BE(codeDirectory->codeLimit))
                        {
                            //只计算 TEXT 段 的 HASH 值
                            /*只计算代码段 text section*/
                            section_t* section_text = main->section_text;
                            if(hash_start + pageSize > section_text->addr + main->slide && hash_start < section_text->addr + main->slide + section_text->size)
                            {
                                chkshaOfData((unsigned char*)hash_start, pageSize, mode, pageHash);
                                uint8_t* hashSlot = (uint8_t*)((uint8_t*)codeDirectory + BE(codeDirectory->hashOffset) + codeDirectory->hashSize*i);
                                if(!memoryEqual(pageHash, hashSlot , hashSize))
                                {
                                    // 正版APP 加密区段 加白
                                    uint32_t hash_off = (uint32_t)(hash_start - start);
                                    
                                    if(!(main->encrypt.encrypted && ((hash_off >= main->encrypt.offset && hash_off < main->encrypt.offset + main->encrypt.size) ||
                                    (hash_off + pageSize >= main->encrypt.offset && hash_off + pageSize < main->encrypt.offset + main->encrypt.size))))
                                    {
                                        patches["code"].push_back(stringAppendInt(OBF("SlotCheck: text_command: "), i));
                                    }
                                }
                            }
                            
                        }
                    }
                }
                
                // 计算整个 CodeDirectory的 hash 值
                
                //const char* codeDirectory_SHA = chkshaOfDataToBase64((unsigned char*)codeDirectory, (long)BE(codeDirectory->length), mode);
                unsigned char digest[hashSize];
                chksha((unsigned char*)codeDirectory, BE(codeDirectory->length), mode, digest);
                const char* codeDirectory_SHA = base64_encode(digest, 20);  //取前20字节计算base64
                const char* CDHash = hashSize == 32 ? getMainSignInfo().digestHash2:getMainSignInfo().digestHash;
                
                if(!stringEqual(codeDirectory_SHA, CDHash))
                {
                    if(CDHash && strlen(CDHash) == 0)
                    {
                        //CMS签名直接被清了
                        patches[OBF("cdhash")].push_back(OBF("CDHashCheck: empty cdhash"));
                    }
                    else
                    {
                        patches[OBF("cdhash")].push_back(OBF("CDHashCheck: codeDirectory"));
                    }
                    
                }
                
            }
            else
            {
                // CodeDirectory = NULL
            }
            
            // 用公钥验证 signature 字段 ， 再用解密 后的 值 看是否 等于 signAttr 哈希计算后的 值
            // 参数1 公钥指针，参数2 公钥指针长度，参数3 哈希值指针，参数4 哈希值指针长度， 参数5 签名指着， 参数6 签名指针x长度
    //        SignInfo info = getMainSignInfo();
    //        hashSize = stringEqual(info.algorithm, "sha256")?32:20;
    //
    //        unsigned char digest [hashSize];
    //
    //        chkshaOfData((unsigned char*)info.signAttrRaw, (long)info.signAttrRawSize, info.algorithm, digest);
    //
    //        if(!chkPublicKeyVerify(info.certInfo.pubKey.pubKeyRSA.mod, info.certInfo.pubKey.pubKeyRSA.modLen,info.certInfo.pubKey.pubKeyRSA.exp, info.certInfo.pubKey.pubKeyRSA.expLen,digest , hashSize, (unsigned char*)info.signature, (long)info.signatureSize))
    //        {
    //            patches.push_back("SignatureCheck: SignedAttrs");
    //        }
            
            free(path);
        }
    });
    
    return patches;
}