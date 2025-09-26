#!/usr/local/bin/python
# coding: latin-1

import idaapi
import idc
import ida_bytes


def get_static_client_count(cfunc):
   
    class visitor(idaapi.ctree_visitor_t):
      
        def __init__(self, cfunc):
            self.result_client_count = 0
            idaapi.ctree_visitor_t.__init__(self, idaapi.CV_FAST)

        def visit_expr(self, i):

            if self.result_client_count != 0:
                return 0
          
            if i.op == idaapi.cot_uge or i.op == idaapi.cot_ult:
                try:
                    if i.y.op == idaapi.cot_num:
                        print(f"cot_num found {hex(i.y.n._value)}")
                        self.result_client_count = i.y.n._value

                except Exception:
                    print(f"exception in visit_expr")

            return 0       
   
    v = visitor(cfunc)
    v.apply_to(cfunc.body, None)
    return v.result_client_count


def get_client_info_count():
    
    func_ea = idaapi.get_name_ea(BADADDR, "PdcValidateClient")
    print(f"PdcValidateClient address {hex(func_ea)}")
    cfunc = idaapi.decompile(func_ea)
    res = get_static_client_count(cfunc)
    
    return res


pdc_client_info = idaapi.get_name_ea(BADADDR, "PdcClientInfo")
print(f"PdcClientInfo address {hex(pdc_client_info)}")

client_count = get_client_info_count()
print(f"PdcClientInfo array size {client_count}")
client_index = 0

while client_index < client_count:
    
    client_info = pdc_client_info + client_index * 0x18
    flags = ida_bytes.get_dword(client_info)
    name_ea = ida_bytes.get_qword(client_info + 0x10)
    client_name_bytes = ida_bytes.get_strlit_contents(name_ea, -1, idc.get_str_type(name_ea))
    client_name = client_name_bytes.decode('utf-8')
    
    mode = "UserMode"
    if flags & 0x200:
        mode = "KernelMode"
    
    print(f"ClientIndex {hex(client_index)}: flags {hex(flags)} ({mode}) Client name \"{client_name}\"")
    client_index = client_index + 1
