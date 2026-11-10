#Bytecode instructions
| Mnemonic | Opcode Name |  Exists in |  Count |
| :---- | :---- | :----- | -----: |
| [aload_n](https://docs.oracle.com/javase/specs/jvms/se23/html/jvms-6.html#jvms-6.5.aload_n) | [Load](utils/jvm/opcode.py?plain=1#L838) |  CWE470_Graph CWE502_Graph | 87 |
| [if_cond](https://docs.oracle.com/javase/specs/jvms/se23/html/jvms-6.html#jvms-6.5.if_cond) | [Ifz](utils/jvm/opcode.py?plain=1#L1058) |  | 51 |
| [invokevirtual](https://docs.oracle.com/javase/specs/jvms/se23/html/jvms-6.html#jvms-6.5.invokevirtual) | [InvokeVirtual](utils/jvm/opcode.py?plain=1#L476) |  CWE470_Graph | 45 |
| [ldc](https://docs.oracle.com/javase/specs/jvms/se23/html/jvms-6.html#jvms-6.5.ldc) | [Push](utils/jvm/opcode.py?plain=1#L104) |  | 39 |
| [return](https://docs.oracle.com/javase/specs/jvms/se23/html/jvms-6.html#jvms-6.5.return) | [Return](utils/jvm/opcode.py?plain=1#L1280) |  CWE470_Graph CWE502_Graph | 30 |
| [invokestatic](https://docs.oracle.com/javase/specs/jvms/se23/html/jvms-6.html#jvms-6.5.invokestatic) | [InvokeStatic](utils/jvm/opcode.py?plain=1#L511) |  CWE502_Graph | 21 |
| [pop](https://docs.oracle.com/javase/specs/jvms/se23/html/jvms-6.html#jvms-6.5.pop) | [Pop](utils/jvm/opcode.py?plain=1#L195) |  CWE502_Graph | 18 |
| [goto](https://docs.oracle.com/javase/specs/jvms/se23/html/jvms-6.html#jvms-6.5.goto) | [Goto](utils/jvm/opcode.py?plain=1#L1240) |  CWE502_Graph | 18 |
| [astore_n](https://docs.oracle.com/javase/specs/jvms/se23/html/jvms-6.html#jvms-6.5.astore_n) | [Store](utils/jvm/opcode.py?plain=1#L685) |  CWE502_Graph | 15 |
| [new](https://docs.oracle.com/javase/specs/jvms/se23/html/jvms-6.html#jvms-6.5.new) | [New](utils/jvm/opcode.py?plain=1#L1128) |  CWE470_Graph | 12 |
| [dup](https://docs.oracle.com/javase/specs/jvms/se23/html/jvms-6.html#jvms-6.5.dup) | [Dup](utils/jvm/opcode.py?plain=1#L284) |  CWE470_Graph | 12 |
| [invokespecial](https://docs.oracle.com/javase/specs/jvms/se23/html/jvms-6.html#jvms-6.5.invokespecial) | [InvokeSpecial](utils/jvm/opcode.py?plain=1#L584) |  CWE470_Graph | 12 |
| [aload](https://docs.oracle.com/javase/specs/jvms/se23/html/jvms-6.html#jvms-6.5.aload) | [Load](utils/jvm/opcode.py?plain=1#L838) |  | 3 |
