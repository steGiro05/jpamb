#Bytecode instructions
| Mnemonic | Opcode Name |  Exists in |  Count |
| :---- | :---- | :----- | -----: |
| [aload_n](https://docs.oracle.com/javase/specs/jvms/se23/html/jvms-6.html#jvms-6.5.aload_n) | [Load](utils/jvm/opcode.py?plain=1#L838) |  CWE470_Dict CWE470_Graph CWE470_Naive CWE502_Dict CWE502_Graph CWE502_Naive taint_cases | 472 |
| [ldc](https://docs.oracle.com/javase/specs/jvms/se23/html/jvms-6.html#jvms-6.5.ldc) | [Push](utils/jvm/opcode.py?plain=1#L104) |  CWE470_Dict CWE470_Naive CWE502_Dict CWE502_Graph taint_cases | 310 |
| [invokevirtual](https://docs.oracle.com/javase/specs/jvms/se23/html/jvms-6.html#jvms-6.5.invokevirtual) | [InvokeVirtual](utils/jvm/opcode.py?plain=1#L476) |  CWE470_Dict CWE470_Graph CWE502_Dict taint_cases | 296 |
| [return](https://docs.oracle.com/javase/specs/jvms/se23/html/jvms-6.html#jvms-6.5.return) | [Return](utils/jvm/opcode.py?plain=1#L1280) |  CWE470_Dict CWE470_Graph CWE470_Naive CWE502_Dict CWE502_Graph CWE502_Naive taint_cases | 249 |
| [if_cond](https://docs.oracle.com/javase/specs/jvms/se23/html/jvms-6.html#jvms-6.5.if_cond) | [Ifz](utils/jvm/opcode.py?plain=1#L1058) |  CWE470_Dict CWE502_Dict taint_cases | 195 |
| [invokestatic](https://docs.oracle.com/javase/specs/jvms/se23/html/jvms-6.html#jvms-6.5.invokestatic) | [InvokeStatic](utils/jvm/opcode.py?plain=1#L511) |  CWE470_Dict CWE470_Naive CWE502_Dict CWE502_Graph CWE502_Naive taint_cases | 125 |
| [goto](https://docs.oracle.com/javase/specs/jvms/se23/html/jvms-6.html#jvms-6.5.goto) | [Goto](utils/jvm/opcode.py?plain=1#L1240) |  CWE502_Dict CWE502_Graph CWE502_Naive taint_cases | 118 |
| [iconst_i](https://docs.oracle.com/javase/specs/jvms/se23/html/jvms-6.html#jvms-6.5.iconst_i) | [Push](utils/jvm/opcode.py?plain=1#L104) |  | 86 |
| [astore_n](https://docs.oracle.com/javase/specs/jvms/se23/html/jvms-6.html#jvms-6.5.astore_n) | [Store](utils/jvm/opcode.py?plain=1#L685) |  CWE470_Dict CWE502_Dict CWE502_Graph CWE502_Naive taint_cases | 82 |
| [if_icmp_cond](https://docs.oracle.com/javase/specs/jvms/se23/html/jvms-6.html#jvms-6.5.if_icmp_cond) | [If](utils/jvm/opcode.py?plain=1#L877) |  CWE470_Naive | 70 |
| [pop](https://docs.oracle.com/javase/specs/jvms/se23/html/jvms-6.html#jvms-6.5.pop) | [Pop](utils/jvm/opcode.py?plain=1#L195) |  CWE502_Dict CWE502_Graph CWE502_Naive | 66 |
| [iload](https://docs.oracle.com/javase/specs/jvms/se23/html/jvms-6.html#jvms-6.5.iload) | [Load](utils/jvm/opcode.py?plain=1#L838) |  | 61 |
| [aload](https://docs.oracle.com/javase/specs/jvms/se23/html/jvms-6.html#jvms-6.5.aload) | [Load](utils/jvm/opcode.py?plain=1#L838) |  | 57 |
| [new](https://docs.oracle.com/javase/specs/jvms/se23/html/jvms-6.html#jvms-6.5.new) | [New](utils/jvm/opcode.py?plain=1#L1128) |  CWE470_Graph taint_cases | 51 |
| [dup](https://docs.oracle.com/javase/specs/jvms/se23/html/jvms-6.html#jvms-6.5.dup) | [Dup](utils/jvm/opcode.py?plain=1#L284) |  CWE470_Graph taint_cases | 51 |
| [invokespecial](https://docs.oracle.com/javase/specs/jvms/se23/html/jvms-6.html#jvms-6.5.invokespecial) | [InvokeSpecial](utils/jvm/opcode.py?plain=1#L584) |  CWE470_Graph taint_cases | 51 |
| [astore](https://docs.oracle.com/javase/specs/jvms/se23/html/jvms-6.html#jvms-6.5.astore) | [Store](utils/jvm/opcode.py?plain=1#L685) |  | 42 |
| [aaload](https://docs.oracle.com/javase/specs/jvms/se23/html/jvms-6.html#jvms-6.5.aaload) | [ArrayLoad](utils/jvm/opcode.py?plain=1#L408) |  | 39 |
| [iload_n](https://docs.oracle.com/javase/specs/jvms/se23/html/jvms-6.html#jvms-6.5.iload_n) | [Load](utils/jvm/opcode.py?plain=1#L838) |  CWE470_Naive | 30 |
| [istore](https://docs.oracle.com/javase/specs/jvms/se23/html/jvms-6.html#jvms-6.5.istore) | [Store](utils/jvm/opcode.py?plain=1#L685) |  | 27 |
| [arraylength](https://docs.oracle.com/javase/specs/jvms/se23/html/jvms-6.html#jvms-6.5.arraylength) | [ArrayLength](utils/jvm/opcode.py?plain=1#L442) |  | 20 |
| [iinc](https://docs.oracle.com/javase/specs/jvms/se23/html/jvms-6.html#jvms-6.5.iinc) | [Incr](utils/jvm/opcode.py?plain=1#L1207) |  | 20 |
| [isub](https://docs.oracle.com/javase/specs/jvms/se23/html/jvms-6.html#jvms-6.5.isub) | [Binary](utils/jvm/opcode.py?plain=1#L801) |  CWE470_Dict CWE502_Dict | 16 |
| [iadd](https://docs.oracle.com/javase/specs/jvms/se23/html/jvms-6.html#jvms-6.5.iadd) | [Binary](utils/jvm/opcode.py?plain=1#L801) |  CWE470_Naive | 15 |
| [istore_n](https://docs.oracle.com/javase/specs/jvms/se23/html/jvms-6.html#jvms-6.5.istore_n) | [Store](utils/jvm/opcode.py?plain=1#L685) |  | 12 |
| [invokedynamic](https://docs.oracle.com/javase/specs/jvms/se23/html/jvms-6.html#jvms-6.5.invokedynamic) | [InvokeDynamic](utils/jvm/opcode.py?plain=1#L634) |  | 8 |
| [irem](https://docs.oracle.com/javase/specs/jvms/se23/html/jvms-6.html#jvms-6.5.irem) | [Binary](utils/jvm/opcode.py?plain=1#L801) |  | 6 |
