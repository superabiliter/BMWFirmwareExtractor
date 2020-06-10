'''

SectorHeader 9 Bytes

    Unknown 3 Bytes

    HeaderLength 4 Bytes

    Unknown 2 Bytes



FileHeader 

    Configure Total - 9

    FileContent 9 Bytes

        Unknown 3 Bytes

        FileLength 4 Bytes

        Unknown 2 Bytes

'''



import zlib

import struct

import os





DEST = "/home/ltdzzzz/Desktop/mguroot"



# NBT EVO version

class SectorHeader:

    def __init__(self, data):

        if len(data) != 9:

            raise("SectorHeader: Unexpected data length!")

        header = struct.unpack("<3sIBB",data)

        self._unknown0 = header[0]

        self._headerLength = header[1]

        self._hasFile = header[2]

        self._unknown1 = header[3]



    def getHeaderLength(self):

        if self._hasFile:

            return self._headerLength + 9

        else:

            return self._headerLength



    def hasFile(self):

        if self._hasFile !=0 :

            return True

        else:

            return False



class FileHeader:

    def __init__(self, data, hasFile):

        # if len(data) < 9:

        #     raise("FileHeader: Unexpected data length!")

        if hasFile:

            header = struct.unpack("<3sIH",data[-9:])

            self._unknown0 = header[0]

            self._fileLength = header[1]

            self._unknown1 = header[2]

            rawConfig = data[:-9]

        else:

            self._fileLength = 0

            rawConfig = data

        self._config = self.generateConfig(rawConfig)



    def getFileLength(self):

        return self._fileLength



    def generateConfig(self,cfg):

        config = {}

        if len(cfg) == 0:

            return config

        items = cfg.split(b";")[:-1]

        for i in items:

            idx = i.find(b"=")

            key = i[:idx]

            value = i[idx+1:]

            config[key] = value

        return config



    def getConfig(self):

        return self._config



def Handle_NBT_EVO(name):

    fp = open(name,"rb")

    fp.seek(10)

    c = 0

    while True:

        d = fp.read(9)

        if len(d) < 9:

            break

        c += 1

        sectorHeader = SectorHeader(d)

        

        fileHeaderLength = sectorHeader.getHeaderLength()

        d = fp.read(fileHeaderLength)

        fileHeader = FileHeader(d,sectorHeader.hasFile())

        fconfig = fileHeader.getConfig()

        fileLength = fileHeader.getFileLength()

        fp.seek(fileLength,1)

        

        print("File number: %d"%c)

        print("File size: 0x%x"%fileLength)

        print("File info:")

        for x in fconfig:

            print("%24s%40s"%(bytes.decode(x),bytes.decode(fconfig[x])))



        input(">")



    print("Analysis is done!")





class Block:

    def __init__(self,fp):

        print("Block start address 0x%x"%fp.tell())

        self._fp = fp

        self._flag = self.getByte(3)

        self._nameLength = self.getShort(4)

        self._subnameLength = self.getShort(6)

        

        self._compressedFileSize = self.getInt(0xC)

        self._rawFileSize = self.getInt(0x10)

        self._fileSize = self.getInt(0x50)

        if self._rawFileSize == 0: 

            if self._subnameLength == 0:

                self._isDir = True

                self._isLink = False

            else:

                self._isDir = False

                self._isLink = True

        else:

            self._isDir = False

            self._isLink = False

        

        name_idx = 0x5C

        name = self.getBytes(name_idx,self._nameLength)

        self._name = bytes.decode(name).strip()

        subname_idx = 0x5C + self._nameLength

        subname = self.getBytes(subname_idx,self._subnameLength)

        self._subname = bytes.decode(subname).strip()

        data_idx = 0x5C + self._nameLength + self._subnameLength

        if self._flag != b"\x82":

            data_idx += 0x1C

        data = self.getBytes(data_idx,self._compressedFileSize)

        self._data = data

        next_idx = data_idx + self._compressedFileSize

        self._fp.seek(next_idx,1)

        return



    def getInt(self,idx):

        self._fp.seek(idx,1)

        data = self._fp.read(4)

        self._fp.seek(-(idx+4),1)

        return struct.unpack("<I",data)[0]



    def getShort(self,idx):

        self._fp.seek(idx,1)

        data = self._fp.read(2)

        self._fp.seek(-(idx+2),1)

        return struct.unpack("<H",data)[0]



    def getByte(self,idx):

        return self.getBytes(idx,1)



    def getBytes(self,idx,l):

        self._fp.seek(idx,1)

        data = self._fp.read(l)

        self._fp.seek(-(idx+l),1)

        return data



    def getRawFile(self):

        if self._compressedFileSize == self._rawFileSize:

            return self._data

        else:

            return zlib.decompress(self._data)



    def genItem(self):

        if self._isDir:

            return self.genDir()

        if self._isLink:

            return self.genLink()

        return self.genFile()        

    

    def setRoot(self,path):

        self._root = path



    def genFile(self):

        name = self._name[1:]

        try:

            dname = os.path.dirname(name)

            dirname = os.path.join(self._root,dname)

            basename = os.path.basename(name)

            filename = os.path.join(dirname,basename)

            if not os.path.exists(dirname):

                os.makedirs(dirname)

            fp = open(filename,"wb")

            fp.write(self.getRawFile())

            fp.close()

            return True

        except Exception as e:

            print(e)

            return False



    def genDir(self):

        name = self._name[1:]

        try:

            dirname = os.path.join(self._root,name)

            if not os.path.exists(dirname):

                os.makedirs(dirname)

            return True

        except Exception as e:

            print(e)

            return False



    def genLink(self):

        if self._subname[0] == b"/":

            return False

        else:

            basename = os.path.basename(self._name)

            dirname = os.path.dirname(self._name)[1:]

            work_root = os.path.join(DEST,dirname)

            os.chdir(work_root)

            print(work_root)

            print(basename)

            print(self._subname)

            if os.path.exists(self._subname):

                return True

            os.symlink(basename,self._subname)

            os.chmod(self._subname,0x777)

            return True



def getAddrFromXML(data):

    res = []

    idx = 0

    while True:

        s = data.find(b"<SOURCE-START-ADDRESS>", idx)

        if s == -1:

            return res

        idx = s + 1

        e = data.find(b"</SOURCE-START-ADDRESS>", idx)

        idx = e + 1

        s += 22

        start = int(data[s:e],16)

        s = data.find(b"<SOURCE-END-ADDRESS>", idx)

        idx = s + 1

        e = data.find(b"</SOURCE-END-ADDRESS>", idx)

        idx = e + 1

        s += 20

        end = int(data[s:e],16)

        res.append((start,end))





def getXMLFromDir(path):

    xmls = []

    for root, dirs, files in os.walk(path):

        for xml_file in files:

            if ".xml." in xml_file:

                xmls.append(os.path.join(root,xml_file))

    return xmls               

                



def startJob(xmls):

    for x in xmls:

        print(x)

        root = os.path.dirname(x)

        xml_name = os.path.basename(x)

        r = xml_name.split(".xml.")

        if len(r) != 2:

            continue

        name = r[0]

        version = r[1]

        fp = open(x,'rb')

        xml_c = fp.read()

        fp.close()

        addrs = getAddrFromXML(xml_c)       

        fw_name = name + ".bin." + version

        fw_path = os.path.join(root,fw_name)

        print(fw_path)

        # dest = os.path.join(DEST,name)

        dest = DEST

        print(dest)

        fp = open(fw_path,"rb")

        addrs = addrs[2:]

        for addr in addrs:

            start = addr[0]

            print(start)

            end = addr[1]

            fp.seek(start+0x40,0)

            while True:

                idx = fp.tell()

                if idx >= end:

                    break

                block = Block(fp)

                block.setRoot(dest)

                # print("File name: %s"%block._name)

                # print("Sub file name: %s"%block._subname)

                # print("Compressed size: 0x%x"%block._compressedFileSize)

                # print("Raw size: 0x%x"%block._rawFileSize)

                # print("File size: 0x%x"%block._fileSize)

                if block.genItem():

                    print("File/Dir generate successful!")

                else:

                    print("File name: %s"%block._name)

                    print("Sub file name: %s"%block._subname)

                    print("Error!")

        fp.close()



def Handle_MGU():

   xmls = getXMLFromDir("/home/ltdzzzz/Desktop/MGU")

   startJob(xmls)



Handle_MGU()
