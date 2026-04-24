# Converts a firmware bin file to a c header file
def firmware_bin_convert(inFile: str, outFile: str):
    with open(inFile, "rb") as f:    
        # Read firmware bin file
        firmware_bin = f.read()

    with open(outFile, "w") as f:
        # Write header
        f.write("#include <Arduino.h>\n\n")
        f.write(f"#define FIRMWARE_LEN {len(firmware_bin)}\n\n")
        
        f.write("PROGMEM const unsigned char firmware_bin[] = {\n")

        # Write data
        for i, byte in enumerate(firmware_bin):
            if i % 16 == 0:
                f.write("    ")
            f.write(f"0x{byte:02X}, ")
            if i % 16 == 15 or i == len(firmware_bin) - 1:
                f.write("\n")
        
        # Write footer
        f.write("};\n")

# Converts a firmware CLM file to a c header file
def firmware_clm_convert(inFile: str, outFile: str):
    with open(inFile, "rb") as f:    
        # Read firmware clm blob file
        firmware_clm = f.read()

    with open(outFile, "w") as f:
        # Write header
        f.write("#include <Arduino.h>\n\n")
        f.write(f"#define FIRMWARE_CLM_LEN {len(firmware_clm)}\n\n")
        
        f.write("PROGMEM const unsigned char firmware_clm[] = {\n")

        # Write data
        for i, byte in enumerate(firmware_clm):
            if i % 16 == 0:
                f.write("    ")
            f.write(f"0x{byte:02X}, ")
            if i % 16 == 15 or i == len(firmware_clm) - 1:
                f.write("\n")
        
        # Write footer
        f.write("};\n")

#firmware_clm_convert("cyfmac43430-sdio.1DX.clm_blob", "cyfmac43430-sdio-1DX-clm_blob.c")
firmware_bin_convert("brcmfmac43436s-sdio.bin", "brcmfmac43436s-sdio.c")