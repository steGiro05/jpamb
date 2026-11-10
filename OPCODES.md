#Bytecode instructions
| Mnemonic | Opcode Name |  Exists in |  Count |
| :---- | :---- | :----- | -----: |
| [aload_n](https://docs.oracle.com/javase/specs/jvms/se23/html/jvms-6.html#jvms-6.5.aload_n) | [Load](utils/jvm/opcode.py?plain=1#L838) |  CWE470_Dict CWE470_Naive | 78 |
| [return](https://docs.oracle.com/javase/specs/jvms/se23/html/jvms-6.html#jvms-6.5.return) | [Return](utils/jvm/opcode.py?plain=1#L1280) |  CWE470_Dict CWE470_Naive | 75 |
| [ldc](https://docs.oracle.com/javase/specs/jvms/se23/html/jvms-6.html#jvms-6.5.ldc) | [Push](utils/jvm/opcode.py?plain=1#L104) |  CWE470_Dict CWE470_Naive | 54 |
| [invokevirtual](https://docs.oracle.com/javase/specs/jvms/se23/html/jvms-6.html#jvms-6.5.invokevirtual) | [InvokeVirtual](utils/jvm/opcode.py?plain=1#L476) |  CWE470_Dict | 51 |
| [if_cond](https://docs.oracle.com/javase/specs/jvms/se23/html/jvms-6.html#jvms-6.5.if_cond) | [Ifz](utils/jvm/opcode.py?plain=1#L1058) |  CWE470_Dict | 33 |
| [invokestatic](https://docs.oracle.com/javase/specs/jvms/se23/html/jvms-6.html#jvms-6.5.invokestatic) | [InvokeStatic](utils/jvm/opcode.py?plain=1#L511) |  CWE470_Dict CWE470_Naive | 27 |
| [iconst_i](https://docs.oracle.com/javase/specs/jvms/se23/html/jvms-6.html#jvms-6.5.iconst_i) | [Push](utils/jvm/opcode.py?plain=1#L104) |  | 18 |
| [if_icmp_cond](https://docs.oracle.com/javase/specs/jvms/se23/html/jvms-6.html#jvms-6.5.if_icmp_cond) | [If](utils/jvm/opcode.py?plain=1#L877) |  CWE470_Naive | 15 |
| [iload_n](https://docs.oracle.com/javase/specs/jvms/se23/html/jvms-6.html#jvms-6.5.iload_n) | [Load](utils/jvm/opcode.py?plain=1#L838) |  CWE470_Naive | 12 |
| [astore_n](https://docs.oracle.com/javase/specs/jvms/se23/html/jvms-6.html#jvms-6.5.astore_n) | [Store](utils/jvm/opcode.py?plain=1#L685) |  CWE470_Dict | 9 |
| [aaload](https://docs.oracle.com/javase/specs/jvms/se23/html/jvms-6.html#jvms-6.5.aaload) | [ArrayLoad](utils/jvm/opcode.py?plain=1#L408) |  | 9 |
| [isub](https://docs.oracle.com/javase/specs/jvms/se23/html/jvms-6.html#jvms-6.5.isub) | [Binary](utils/jvm/opcode.py?plain=1#L801) |  CWE470_Dict | 6 |
| [aload](https://docs.oracle.com/javase/specs/jvms/se23/html/jvms-6.html#jvms-6.5.aload) | [Load](utils/jvm/opcode.py?plain=1#L838) |  | 3 |
| [arraylength](https://docs.oracle.com/javase/specs/jvms/se23/html/jvms-6.html#jvms-6.5.arraylength) | [ArrayLength](utils/jvm/opcode.py?plain=1#L442) |  | 3 |
| [iadd](https://docs.oracle.com/javase/specs/jvms/se23/html/jvms-6.html#jvms-6.5.iadd) | [Binary](utils/jvm/opcode.py?plain=1#L801) |  CWE470_Naive | 3 |
