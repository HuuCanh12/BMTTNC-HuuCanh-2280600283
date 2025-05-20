so_gio_lam = float(input("Nhập số giờ làm mỗi tuần: "))
luong_gio = float(input("Nhập mức lương trên mỗi giờ tiêu chuẩn: "))
gio_tieu_chuan = 40
gio_vuot_chuan = max(0, so_gio_lam - gio_tieu_chuan) 
luong_vuot_chuan = luong_gio * 1.5 

thuc_linh = gio_tieu_chuan * luong_gio + gio_vuot_chuan * luong_vuot_chuan
print(f"Số tiền thực lĩnh của nhân viên (thực lĩnh): {thuc_linh}")