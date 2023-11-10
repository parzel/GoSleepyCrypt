import re

with open("run.c", "r") as f:
    lines = f.readlines()
    lines = [x.strip() for x in lines]


counter = 0
for l in lines:
    if "_printf(" in l:
        match = re.match("_printf\(\"(.*)\",", l)
        if match:
            first = match[1]
            mod_first = [f"'{x}'" for x in first]
            mod_first = ",".join(mod_first)
            print("CHAR x"+str(counter)+"[] = {"+mod_first+", '\\n' , 0x00};")
            print(l.replace(f"\"{first}\"", f"x{counter}"))
            counter += 1
    else:
        print(l)
