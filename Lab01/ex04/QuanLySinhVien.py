from SinhVien import SinhVien

class   QuanLySinhVien:
    listSinhVien = []

    def generateID (self):
        maxId = 1
        if (self.soLuongSinhVien()>0):
            maxId = self.listSinhVien[0]._id
            for sv in self.listSinhVien:
                if(maxId<sv._id):
                    maxId = sv._id
            maxId = maxId + 1
        return maxId
    def soLuongSinhVien(self):
        return self.listSinhVien.__len__()

    def nhapSinhVien(self):
        svId = self.generateID()
        name = input("Nhap ten sv: ")
        sex = input("Nhap gioi tinh: ")
        major = input("Nhap chuyen nganh: ")
        diemTB = float(input("Nhap diem tb: "))
        sv = SinhVien (svId, name, sex, major, diemTB)
        self.xepLoaiHocLuc(sv)
        self.listSinhVien.append(sv)
    def updateSinhVien(self, ID):
        sv:SinhVien = self.findByID(ID)
        if( sv != None):
            name = input("Nhap ten sv: ")
            sex = input("Nhap gioi tinh: ")
            major = input("Nhap chuyen nganh: ")
            diemTB = float(input("Nhap diem tb: "))
            sv._name = name
            sv._sex =sex
            sv._major = major
            sv._diemTB = diemTB
            self.xepLoaiHocLuc(sv)
        else:
            print("Sinh vien co ID = {} ko ton tai.".format(ID))
    def sortByID(self):
        self.listSinhVien.sort(key = lambda x: x._id, reverse=False)
    def sortByName(self):
        self.listSinhVien.sort(key = lambda x: x._name, reverse=False)
    def sortByDiemTB(self):
        self.listSinhVien.sort(key = lambda x: x._diemTB, reverse=False)
    def findByID(self, ID):
        searchResult = None
        if( self.soLuongSinhVien()>0):
            for sv in self.listSinhVien:
                if(sv._id == ID):
                    searchResult = sv
        return searchResult
    def findByName(self, keyword):
        listSV = []
        if(self.soLuongSinhVien()>0 ):
            for sv in self.listSinhVien:
                if(keyword.upper() in sv._name.upper()):
                    listSV.append(sv)
        return listSV
    def deleteById (self, ID):
        isDeleted = False
        sv= self.findByID(ID)
        if(sv != None):
            self.listSinhVien.remove(sv)
            isDeleted = True 
        return isDeleted
    def xepLoaiHocLuc(self, sv:SinhVien):
        if(sv._diemTB >= 8):
            sv._HocLuc = "Gioi"
        elif (sv._diemTB >= 6.5):
            sv._HocLuc = "Kha"
        elif (sv._diemTB >= 5):
            sv._HocLuc = "TB"
        else:
            sv._HocLuc = "Yeu"
    def showSinhVien(self, listSV):
        print("{:<8} {:<18} {:<8} {:<8} {:<8} {:<8}".format("ID", "Name", "Sex", "Major", "Diem TB", "Hoc\nLuc"))
        if (listSV.__len__() > 0):
            for sv in listSV:
                print("{:<8} {:<18} {:<8} {:<8} {:<8} {:<8}".format(
                sv.sv_id, sv.sv_name, sv.sv_sex, sv.sv_major, sv.sv_diemTB, sv.sv_hocLuc
            ))
        print("\n")

    def getListSinhVien(self):
        return self.listSinhVien