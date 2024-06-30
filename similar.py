import pefile
import os
import sys
import argparse

def main():
    parser = argparse.ArgumentParser(description='Make a payload similar to a binary')
    parser.add_argument('--payload', dest='payload', type=str, help='PE file to modify')
    parser.add_argument('--origin', dest='origin', type=str, help='PE file to get section data from')
    parser.add_argument('--blacklist', dest='section_blacklist', type=str, default=".rsrc,.reloc,.pdata", help='Sections to ignore')
    parser.add_argument('--out', dest='out', type=str, default="similar.h", help='Output header file')

    args = parser.parse_args()

    blacklist = args.section_blacklist.split(',')

    if not os.path.exists(args.payload):
        print("%s does not exist" % args.payload)
        sys.exit(1)

    if not os.path.exists(args.origin):
        print("%s does not exist" % args.origin)
        sys.exit(2)

    pe_origin = pefile.PE(args.origin)
    pe_payload = pefile.PE(args.payload)
 
    print("=== Payload binary information ===")
    print("Sections:")
    payload_section_dict = {}
    for section in pe_payload.sections:
        section_name = section.Name.decode().rstrip("\x00")
        print(" - %s : 0x%x" % (section_name.ljust(10), section.SizeOfRawData))
        payload_section_dict[section_name] = section.SizeOfRawData
 
    print("=== Origin binary information ===")
    print("Sections:")
    tobeadded_dict = {}
    for section in pe_origin.sections:
        section_name = section.Name.decode().rstrip("\x00")
        print(" - %s : 0x%x" % (section_name.ljust(10), section.SizeOfRawData))

        if section_name in blacklist:
            continue

        if not section_name in payload_section_dict:
            tobeadded_dict[section_name] = (True, section.get_data())
        else:
            # Take the begining of the payload. To be changed if necessary
            if payload_section_dict[section_name] < section.SizeOfRawData:
                tobeadded_dict[section_name] = (False, section.get_data()[:section.SizeOfRawData-payload_section_dict[section_name]])

    print("===============================================================================================")
    print("The following sections will be created :")
    for section_name, section_data in tobeadded_dict.items():
        section_created = section_data[0]
        section_data = section_data[1]

        if section_created:
            print(" - %s : %s bytes" % (section_name, hex(len(section_data))))

    print("The following sections will have data added :")
    for section_name, section_data in tobeadded_dict.items():
        section_created = section_data[0]
        section_data = section_data[1]

        if not section_created:
            print(" - %s : %s bytes" % (section_name, hex(len(section_data))))

    print("===============================================================================================")
    h_file  = "/*\n"
    h_file += "* Add this header file to your project to make it similar the selected binary\n"
    h_file += "* Original binary : %s\n" % os.path.basename(args.origin)
    h_file += "*/\n"
    
    for section_name, section_data in tobeadded_dict.items():
        section_created = section_data[0]
        section_data = section_data[1]

        h_file += "\n"
        h_file += "#pragma section(\"%s\")\n" % section_name
        h_file += "__declspec(allocate(\"%s\")) const unsigned char %s[] = {\n" % (section_name, "data_section_%s" % section_name.replace('.', '_'))
        while len(section_data) > 0:
            part = section_data[:16]
            section_data = section_data[16:]
            b_row = [hex(b) for b in part]
            h_file += "    " + ", ".join(b_row)

            if len(section_data) > 0:
                h_file += ",\n"
            else:
                h_file += "\n"
        h_file += "};\n"

        h_file += "\n"

    h_file += "int get_address()\n"
    h_file += "{\n"
    h_file += "\tint res = 0;\n"

    for section_name in tobeadded_dict:
        h_file += "\tres += (int)&data_section_%s;\n" % section_name.replace(".", "_")

    h_file += "\treturn res;\n"
    h_file += "}\n\n"

    h_file += """int add_data()
{
    if (get_address() < 0)
        return 0;
    else
        return 1;
}"""

    f = open(args.out, "w")
    f.write(h_file)
    f.close()

    print("Header file written to %s" % args.out)










if __name__=="__main__":
    main()
