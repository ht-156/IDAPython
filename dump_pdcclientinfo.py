#!/usr/local/bin/python
# coding: latin-1

import idaapi
import idc



  

def get_static_client_count(cfunc):
    
    global result_client_count
    
    result_client_count = 0
   
    class visitor(idaapi.ctree_visitor_t):
      
        def __init__(self, cfunc):
            idaapi.ctree_visitor_t.__init__(self, idaapi.CV_FAST)

        def visit_expr(self, i):
            global result_client_count

            if result_client_count != 0:
                return 0
          
            if i.op == idaapi.cot_uge:
                try:
                    if i.y.op == idaapi.cot_num:
                        print "cot_num found %X\r\n" % (i.y.n._value)
                        result_client_count = i.y.n._value

                except Exception:
                    print "exception in visit_expr\r\n"

            return 0       
   
    v = visitor(cfunc)
    v.apply_to(cfunc.body, None)
    return result_client_count


def get_client_info_count():
    
    func_ea = idaapi.get_name_ea(BADADDR, "PdcValidateClient")
    print "PdcValidateClient address %LX" % (func_ea)
    cfunc = idaapi.decompile(func_ea)
    res = get_static_client_count(cfunc)
    
    return res



pdc_client_info = idaapi.get_name_ea(BADADDR, "PdcClientInfo")
print "PdcClientInfo address 0x%LX" % pdc_client_info

client_count = get_client_info_count()
print "PdcClientInfo array size %X\r\n" % (client_count)
client_index = 0

while client_index < client_count:
    
    client_info = pdc_client_info + client_index * 0x18
    flags = idc.Dword(client_info)
    name_ea = idc.Qword(client_info + 0x10)
    client_name = idc.GetString(name_ea, -1, idc.GetStringType(name_ea))
    
    mode = "UserMode"
    if flags & 0x200:
        mode = "KernelMode"
    
    print "ClientIndex 0x%X: flags %X (%s) Client name \"%s\"" % (client_index, flags, mode, client_name)
    client_index = client_index + 1
