from scapy.all import *

# Returns a table of details from NTLMv2 SSP in SMB packets   
def ntlmv2_smb(pkt) -> str:
    # Create a list of SMB packets
    if pkt.haslayer("SMB2_Session_Setup_Request"):
    # Create a list of SMB packets containing SMB2_Session_Setup_Request
    #ntlmssp_smb_list: list = [{'src': p.src, 'dst': p.dst, 'smb_ssr' : p.getlayer("SMB2_Session_Setup_Request").Buffer[0][1]} for p in smb_list if p.haslayer("SMB2_Session_Setup_Request")]    
        
        try:
            ntlmssp = pkt.getlayer("SMB2_Session_Setup_Request").Buffer[0][1].token.responseToken.value.val
            try:
                ntlmv2_data: dict = {}
                # Extract Target Name (Domain or Server)
                domain_length_raw: bytes = ntlmssp[28:28+2]
                domain_length: int = int.from_bytes(domain_length_raw, 'little')
                domain_offset_raw: bytes = ntlmssp[28+2+2:28+2+2+4]
                domain_offset: int = int.from_bytes(domain_offset_raw, 'little')
                domain: str = ntlmssp[domain_offset:domain_offset+domain_length].decode('UTF-8').replace('\x00', '')
                
                # Add Domain to Dictionary
                ntlmv2_data['domain'] = domain
                
                # Extract User Name
                user_length_raw: bytes = ntlmssp[36:36+2]
                user_length: int = int.from_bytes(user_length_raw, 'little')
                user_offset_raw: bytes = ntlmssp[36+2+2:36+2+2+4]
                user_offset: int = int.from_bytes(user_offset_raw, 'little')
                user: str = ntlmssp[user_offset:user_offset+user_length].decode('UTF-8').replace('\x00', '')

                # Add User Name to Dictionary
                ntlmv2_data['user'] = user

                # Extract Workstation Name
                workstation_length_raw: bytes = ntlmssp[44:44+2]
                workstation_length: int = int.from_bytes(workstation_length_raw, 'little')
                workstation_offset_raw: bytes = ntlmssp[44+2+2:44+2+2+4]
                workstation_offset: int = int.from_bytes(workstation_offset_raw, 'little')
                workstation: str = ntlmssp[workstation_offset:workstation_offset+workstation_length].decode('UTF-8').replace('\x00', '')
                
                # Add Workstation to Dictionary
                ntlmv2_data['workstation'] = workstation
                
                # Extract NTLMSSP length
                ntlm_length_raw: bytes = ntlmssp[20:20+2]
                ntlm_length: int = int.from_bytes(ntlm_length_raw, 'little')

                ntlm_offset_raw: bytes = ntlmssp[20+2+2:20+2+2+4]
                ntlm_offset: int = int.from_bytes(ntlm_offset_raw, 'little')

                # Extract NTLMv2 Response
                ntlmv2_response: bytes = ntlmssp[ntlm_offset + 16:ntlm_offset + ntlm_length]

                # Extract NetBIOS Domain Name
                ntlm_nbtdomain_length_raw: bytes = ntlmv2_response[30:30+2]
                ntlm_nbtdomain_length: int = int.from_bytes(ntlm_nbtdomain_length_raw, 'little')
                ntlm_nbt_domain: str = ntlmv2_response[32:32+ntlm_nbtdomain_length].decode('UTF-8').replace("\x00", '')

                # Add NBT Domain to Dictionary
                ntlmv2_data['ntlm_nbt_domain'] = ntlm_nbt_domain

                # Extract NetBIOS Computer Name
                ntlm_nbt_offset: bytes = ntlmv2_response[32+ntlm_nbtdomain_length+4:]
                ntlm_nbtcomputername_length_raw: bytes = ntlmv2_response[32+ntlm_nbtdomain_length+2:32+ntlm_nbtdomain_length+4]
                ntlm_nbtcomputername_length: int = int.from_bytes(ntlm_nbtcomputername_length_raw, 'little')
                ntlm_nbtcomputername: str = ntlm_nbt_offset[:ntlm_nbtcomputername_length].decode('UTF-8').replace('\x00', '')

                # Add NBT Domain to Dictionary
                ntlmv2_data['ntlm_nbtcomputername'] = ntlm_nbtcomputername

                # Extract NetBIOS DNS Domain Name
                ntlm_nbt_offset: bytes = ntlm_nbt_offset[ntlm_nbtcomputername_length:]
                ntlm_nbt_dnsdomain_length_raw: bytes = ntlm_nbt_offset[2:2+2]
                ntlm_nbt_dnsdomain_length: int = int.from_bytes(ntlm_nbt_dnsdomain_length_raw, 'little')
                ntlm_nbt_dnsdomain: str  = ntlm_nbt_offset[4:ntlm_nbt_dnsdomain_length+2+2].decode('UTF-8').replace('\x00', '')

                # Add NBT Domain to Dictionary
                ntlmv2_data['ntlm_nbt_dnsdomain'] = ntlm_nbt_dnsdomain

                # Extract NetBIOS DNS Computer Name
                ntlm_nbt_offset: bytes = ntlm_nbt_offset[ntlm_nbt_dnsdomain_length+6:]
                ntlm_nbt_dnscomputer_length_raw: bytes = ntlm_nbt_offset[:2]
                ntlm_nbt_dnscomputer_length: int = int.from_bytes(ntlm_nbt_dnscomputer_length_raw, 'little')
                ntlm_nbt_dnscomputer: str  = ntlm_nbt_offset[2:ntlm_nbt_dnscomputer_length+2].decode('UTF-8').replace("\x00", '')

                # Add NBT Domain to Dictionary
                ntlmv2_data['ntlm_nbt_dnscomputer'] = ntlm_nbt_dnscomputer            
                return f"\nNTLMv2 Session Setup Request from {pkt[IP].src} against {pkt[IP].dst}.\nAuthenticated user is {ntlmv2_data['workstation']}.{ntlmv2_data['domain']}\{ntlmv2_data['user']} on computer {ntlmv2_data['ntlm_nbtcomputername']}.{ntlmv2_data['ntlm_nbt_dnsdomain']}"
            except:
                pass
        except:
            pass
    if pkt.haslayer("SMB2_Session_Setup_Response"):
        response = pkt.getlayer("SMB2 Session Setup Response").Buffer[0][1].token.negResult.val
        if response == 0:
            trailing = "!^!"*33
            return f"Server at {pkt[IP].src} sent a 'Successful authentication' message to client {pkt[IP].dst}\n{trailing}"