(benchmark
  :"jpamb.cases.advanced.Extended470.alias_dispatcher!(s'__CANARY__')V" (control
    :coverage (
      :"jpamb.cases.advanced.Extended470.alias_dispatcher:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4 5 7 8 9)
      )
      :"jpamb.cases.advanced.Extended470.buildClassName:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3)
      )
      :"jpamb.cases.advanced.Extended470.canary:()V" (coverage
        :reachable (0)
      )
      :"jpamb.cases.advanced.Extended470.classPrefix:()Ljava/lang/String;" (coverage
        :reachable (0 1)
      )
      :"jpamb.cases.advanced.Extended470.instantiate:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4)
      )
      :"jpamb.cases.advanced.Extended470.resolveAlias:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3 6 7 8 9 12 13 14 15 18 19)
      )
      :"jpamb.cases.advanced.Extended470.weakValidation:(Ljava/lang/String;)Z" (coverage
        :reachable (0 1 2 3 4 5 6 7 8 9 10 11 13)
      )
      :"jpamb.cases.advanced.Extended470$__CANARY__Command.<init>:()V" (coverage
        :reachable (0 1 2)
      )
    )
    :results ("assertion error")
  )
  :"jpamb.cases.advanced.Extended470.alias_dispatcher!(s'export')V" (control
    :coverage (
      :"jpamb.cases.advanced.Extended470.alias_dispatcher:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4 5 7 8 9 10)
      )
      :"jpamb.cases.advanced.Extended470.buildClassName:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3)
      )
      :"jpamb.cases.advanced.Extended470.classPrefix:()Ljava/lang/String;" (coverage
        :reachable (0 1)
      )
      :"jpamb.cases.advanced.Extended470.instantiate:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4 6 7 8 9 12)
      )
      :"jpamb.cases.advanced.Extended470.resolveAlias:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3 4 5)
      )
      :"jpamb.cases.advanced.Extended470.weakValidation:(Ljava/lang/String;)Z" (coverage
        :reachable (0 1 2 3 4 5 6 7 8 9 10 11 13)
      )
      :"jpamb.cases.advanced.Extended470$ExportCommand.<init>:()V" (coverage
        :reachable (0 1 2)
      )
      :"jpamb.cases.advanced.Extended470$SafeCommand.<init>:()V" (coverage
        :reachable (0 1 2)
      )
      :"jpamb.cases.advanced.Extended470$SafeCommand.doAction:()V" (coverage
        :reachable (0)
      )
    )
    :results (ok)
  )
  :"jpamb.cases.advanced.Extended470.allowlist_dispatcher!(s'Safe')V" (control
    :coverage (
      :"jpamb.cases.advanced.Extended470.allowlist_dispatcher:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 3 4 5 7 8 9 10)
      )
      :"jpamb.cases.advanced.Extended470.buildClassName:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3)
      )
      :"jpamb.cases.advanced.Extended470.classPrefix:()Ljava/lang/String;" (coverage
        :reachable (0 1)
      )
      :"jpamb.cases.advanced.Extended470.instantiate:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4 6 7 8 9 12)
      )
      :"jpamb.cases.advanced.Extended470.isAllowed:(Ljava/lang/String;)Z" (coverage
        :reachable (0 1 2 3 20 21 23)
      )
      :"jpamb.cases.advanced.Extended470$SafeCommand.<init>:()V" (coverage
        :reachable (0 1 2)
      )
      :"jpamb.cases.advanced.Extended470$SafeCommand.doAction:()V" (coverage
        :reachable (0)
      )
    )
    :results (ok)
  )
  :"jpamb.cases.advanced.Extended470.allowlist_dispatcher!(s'__CANARY__')V" (control
    :coverage (
      :"jpamb.cases.advanced.Extended470.allowlist_dispatcher:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 3 4 5 6)
      )
      :"jpamb.cases.advanced.Extended470.isAllowed:(Ljava/lang/String;)Z" (coverage
        :reachable (0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 22 23)
      )
    )
    :results (ok)
  )
  :"jpamb.cases.advanced.Extended470.chained_sanitization_dispatcher!(s'Safe')V" (control
    :coverage (
      :"jpamb.cases.advanced.Extended470.buildClassName:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3)
      )
      :"jpamb.cases.advanced.Extended470.chained_sanitization_dispatcher:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 16 17 18 19)
      )
      :"jpamb.cases.advanced.Extended470.classPrefix:()Ljava/lang/String;" (coverage
        :reachable (0 1)
      )
      :"jpamb.cases.advanced.Extended470.firstSanitization:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3 6 7)
      )
      :"jpamb.cases.advanced.Extended470.instantiate:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4 6 7 8 9 12)
      )
      :"jpamb.cases.advanced.Extended470.sanitizeIdentifier:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3 6 7 8 9 12 13)
      )
      :"jpamb.cases.advanced.Extended470.secondSanitization:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3 6 7)
      )
      :"jpamb.cases.advanced.Extended470.thirdSanitization:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3 6 7)
      )
      :"jpamb.cases.advanced.Extended470.weakValidation:(Ljava/lang/String;)Z" (coverage
        :reachable (0 1 2 3 4 5 6 7 8 9 10 11 13)
      )
      :"jpamb.cases.advanced.Extended470$SafeCommand.<init>:()V" (coverage
        :reachable (0 1 2)
      )
      :"jpamb.cases.advanced.Extended470$SafeCommand.doAction:()V" (coverage
        :reachable (0)
      )
    )
    :results (ok)
  )
  :"jpamb.cases.advanced.Extended470.chained_sanitization_dispatcher!(s'__CANARY__')V" (control
    :coverage (
      :"jpamb.cases.advanced.Extended470.buildClassName:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3)
      )
      :"jpamb.cases.advanced.Extended470.canary:()V" (coverage
        :reachable (0)
      )
      :"jpamb.cases.advanced.Extended470.chained_sanitization_dispatcher:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 16 17 18)
      )
      :"jpamb.cases.advanced.Extended470.classPrefix:()Ljava/lang/String;" (coverage
        :reachable (0 1)
      )
      :"jpamb.cases.advanced.Extended470.firstSanitization:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3 6 7)
      )
      :"jpamb.cases.advanced.Extended470.instantiate:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4)
      )
      :"jpamb.cases.advanced.Extended470.sanitizeIdentifier:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3 6 7 8 9 12 13)
      )
      :"jpamb.cases.advanced.Extended470.secondSanitization:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3 6 7)
      )
      :"jpamb.cases.advanced.Extended470.thirdSanitization:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3 6 7)
      )
      :"jpamb.cases.advanced.Extended470.weakValidation:(Ljava/lang/String;)Z" (coverage
        :reachable (0 1 2 3 4 5 6 7 8 9 10 11 13)
      )
      :"jpamb.cases.advanced.Extended470$__CANARY__Command.<init>:()V" (coverage
        :reachable (0 1 2)
      )
    )
    :results ("assertion error")
  )
  :"jpamb.cases.advanced.Extended470.conditional_dispatcher!(s'Safe', 1, 2, 1)V" (control
    :coverage (
      :"jpamb.cases.advanced.Extended470.buildClassName:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3)
      )
      :"jpamb.cases.advanced.Extended470.checkFeatureFlag:(I)Z" (coverage
        :reachable (0 1 2 3 4 6)
      )
      :"jpamb.cases.advanced.Extended470.checkPermission:(I)Z" (coverage
        :reachable (0 1 2 3 4 5 6 8)
      )
      :"jpamb.cases.advanced.Extended470.classPrefix:()Ljava/lang/String;" (coverage
        :reachable (0 1)
      )
      :"jpamb.cases.advanced.Extended470.conditional_dispatcher:(Ljava/lang/String;III)V" (coverage
        :reachable (0 1 2 4 5 6 8 9 10 12 13 14 15 16 17 18 20 21 22 23)
      )
      :"jpamb.cases.advanced.Extended470.instantiate:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4 6 7 8 9 12)
      )
      :"jpamb.cases.advanced.Extended470.sanitizeInput:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3 6 7)
      )
      :"jpamb.cases.advanced.Extended470$SafeCommand.<init>:()V" (coverage
        :reachable (0 1 2)
      )
      :"jpamb.cases.advanced.Extended470$SafeCommand.doAction:()V" (coverage
        :reachable (0)
      )
    )
    :results (ok)
  )
  :"jpamb.cases.advanced.Extended470.conditional_dispatcher!(s'__CANARY__', 1, 2, 1)V" (control
    :coverage (
      :"jpamb.cases.advanced.Extended470.buildClassName:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3)
      )
      :"jpamb.cases.advanced.Extended470.canary:()V" (coverage
        :reachable (0)
      )
      :"jpamb.cases.advanced.Extended470.checkFeatureFlag:(I)Z" (coverage
        :reachable (0 1 2 3 4 6)
      )
      :"jpamb.cases.advanced.Extended470.checkPermission:(I)Z" (coverage
        :reachable (0 1 2 3 4 5 6 8)
      )
      :"jpamb.cases.advanced.Extended470.classPrefix:()Ljava/lang/String;" (coverage
        :reachable (0 1)
      )
      :"jpamb.cases.advanced.Extended470.conditional_dispatcher:(Ljava/lang/String;III)V" (coverage
        :reachable (0 1 2 4 5 6 8 9 10 12 13 14 15 16 17 18 20 21 22)
      )
      :"jpamb.cases.advanced.Extended470.instantiate:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4)
      )
      :"jpamb.cases.advanced.Extended470.sanitizeInput:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3 6 7)
      )
      :"jpamb.cases.advanced.Extended470$__CANARY__Command.<init>:()V" (coverage
        :reachable (0 1 2)
      )
    )
    :results ("assertion error")
  )
  :"jpamb.cases.advanced.Extended470.deep_chain_dispatcher!(s'Safe', s'tenant1', 2, s'production', 1, s'audit1', 1)V" (control
    :coverage (
      :"jpamb.cases.advanced.Extended470.buildClassName:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3)
      )
      :"jpamb.cases.advanced.Extended470.classPrefix:()Ljava/lang/String;" (coverage
        :reachable (0 1)
      )
      :"jpamb.cases.advanced.Extended470.deep_chain_dispatcher:(Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;ILjava/lang/String;I)V" (coverage
        :reachable (0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19)
      )
      :"jpamb.cases.advanced.Extended470.instantiate:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4 6 7 8 9 12)
      )
      :"jpamb.cases.advanced.Extended470.stageFour:(Ljava/lang/String;Ljava/lang/String;I)V" (coverage
        :reachable (0 1 2 4 5 6 8 9 10)
      )
      :"jpamb.cases.advanced.Extended470.stageOne:(Ljava/lang/String;Ljava/lang/String;I)Ljava/lang/String;" (coverage
        :reachable (0 1 2 5 6 7 10 11)
      )
      :"jpamb.cases.advanced.Extended470.stageThree:(Ljava/lang/String;IZ)Ljava/lang/String;" (coverage
        :reachable (0 1 4 5 6 9 10 11)
      )
      :"jpamb.cases.advanced.Extended470.stageTwo:(Ljava/lang/String;Ljava/lang/String;Z)Ljava/lang/String;" (coverage
        :reachable (0 1 4 5 6 7 10 11)
      )
      :"jpamb.cases.advanced.Extended470$SafeCommand.<init>:()V" (coverage
        :reachable (0 1 2)
      )
      :"jpamb.cases.advanced.Extended470$SafeCommand.doAction:()V" (coverage
        :reachable (0)
      )
    )
    :results (ok)
  )
  :"jpamb.cases.advanced.Extended470.deep_chain_dispatcher!(s'__CANARY__', s'tenant1', 2, s'production', 1, s'audit1', 1)V" (control
    :coverage (
      :"jpamb.cases.advanced.Extended470.buildClassName:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3)
      )
      :"jpamb.cases.advanced.Extended470.canary:()V" (coverage
        :reachable (0)
      )
      :"jpamb.cases.advanced.Extended470.classPrefix:()Ljava/lang/String;" (coverage
        :reachable (0 1)
      )
      :"jpamb.cases.advanced.Extended470.deep_chain_dispatcher:(Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;ILjava/lang/String;I)V" (coverage
        :reachable (0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18)
      )
      :"jpamb.cases.advanced.Extended470.instantiate:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4)
      )
      :"jpamb.cases.advanced.Extended470.stageFour:(Ljava/lang/String;Ljava/lang/String;I)V" (coverage
        :reachable (0 1 2 4 5 6 8 9)
      )
      :"jpamb.cases.advanced.Extended470.stageOne:(Ljava/lang/String;Ljava/lang/String;I)Ljava/lang/String;" (coverage
        :reachable (0 1 2 5 6 7 10 11)
      )
      :"jpamb.cases.advanced.Extended470.stageThree:(Ljava/lang/String;IZ)Ljava/lang/String;" (coverage
        :reachable (0 1 4 5 6 9 10 11)
      )
      :"jpamb.cases.advanced.Extended470.stageTwo:(Ljava/lang/String;Ljava/lang/String;Z)Ljava/lang/String;" (coverage
        :reachable (0 1 4 5 6 7 10 11)
      )
      :"jpamb.cases.advanced.Extended470$__CANARY__Command.<init>:()V" (coverage
        :reachable (0 1 2)
      )
    )
    :results ("assertion error")
  )
  :"jpamb.cases.advanced.Extended470.fallback_dispatcher!(s'Safe')V" (control
    :coverage (
      :"jpamb.cases.advanced.Extended470.buildClassName:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3)
      )
      :"jpamb.cases.advanced.Extended470.classPrefix:()Ljava/lang/String;" (coverage
        :reachable (0 1)
      )
      :"jpamb.cases.advanced.Extended470.fallback_dispatcher:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4 5 7 8 9 10)
      )
      :"jpamb.cases.advanced.Extended470.instantiate:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4 6 7 8 9 12)
      )
      :"jpamb.cases.advanced.Extended470.isKnownCommand:(Ljava/lang/String;)Z" (coverage
        :reachable (0 1 2 3 12 13 15)
      )
      :"jpamb.cases.advanced.Extended470.validateOrFallback:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3 4)
      )
      :"jpamb.cases.advanced.Extended470.weakValidation:(Ljava/lang/String;)Z" (coverage
        :reachable (0 1 2 3 4 5 6 7 8 9 10 11 13)
      )
      :"jpamb.cases.advanced.Extended470$SafeCommand.<init>:()V" (coverage
        :reachable (0 1 2)
      )
      :"jpamb.cases.advanced.Extended470$SafeCommand.doAction:()V" (coverage
        :reachable (0)
      )
    )
    :results (ok)
  )
  :"jpamb.cases.advanced.Extended470.fallback_dispatcher!(s'__CANARY__')V" (control
    :coverage (
      :"jpamb.cases.advanced.Extended470.buildClassName:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3)
      )
      :"jpamb.cases.advanced.Extended470.canary:()V" (coverage
        :reachable (0)
      )
      :"jpamb.cases.advanced.Extended470.classPrefix:()Ljava/lang/String;" (coverage
        :reachable (0 1)
      )
      :"jpamb.cases.advanced.Extended470.fallback_dispatcher:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4 5 7 8 9)
      )
      :"jpamb.cases.advanced.Extended470.instantiate:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4)
      )
      :"jpamb.cases.advanced.Extended470.isKnownCommand:(Ljava/lang/String;)Z" (coverage
        :reachable (0 1 2 3 4 5 6 7 8 9 10 11 14 15)
      )
      :"jpamb.cases.advanced.Extended470.sanitizeIdentifier:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3 6 7 8 9 12 13)
      )
      :"jpamb.cases.advanced.Extended470.validateOrFallback:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 5 6 7)
      )
      :"jpamb.cases.advanced.Extended470.weakValidation:(Ljava/lang/String;)Z" (coverage
        :reachable (0 1 2 3 4 5 6 7 8 9 10 11 13)
      )
      :"jpamb.cases.advanced.Extended470$__CANARY__Command.<init>:()V" (coverage
        :reachable (0 1 2)
      )
    )
    :results ("assertion error")
  )
  :"jpamb.cases.advanced.Extended470.indirect_construction_dispatcher!(s'Safe', 1, 1)V" (control
    :coverage (
      :"jpamb.cases.advanced.Extended470.classPrefix:()Ljava/lang/String;" (coverage
        :reachable (0 1)
      )
      :"jpamb.cases.advanced.Extended470.getNamespace:(I)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3 4)
      )
      :"jpamb.cases.advanced.Extended470.getSuffix:(Z)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3)
      )
      :"jpamb.cases.advanced.Extended470.indirect_construction_dispatcher:(Ljava/lang/String;II)V" (coverage
        :reachable (0 1 2 3 4 5 7 8 9 11 12 13 14 15 16 17 18 20 21 22 23 24 25 26 27 28 29 30)
      )
      :"jpamb.cases.advanced.Extended470.instantiate:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4 6 7 8 9 12)
      )
      :"jpamb.cases.advanced.Extended470.sanitizeInput:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3 6 7)
      )
      :"jpamb.cases.advanced.Extended470$SafeCommand.<init>:()V" (coverage
        :reachable (0 1 2)
      )
      :"jpamb.cases.advanced.Extended470$SafeCommand.doAction:()V" (coverage
        :reachable (0)
      )
    )
    :results (ok)
  )
  :"jpamb.cases.advanced.Extended470.indirect_construction_dispatcher!(s'__CANARY__', 1, 1)V" (control
    :coverage (
      :"jpamb.cases.advanced.Extended470.canary:()V" (coverage
        :reachable (0)
      )
      :"jpamb.cases.advanced.Extended470.classPrefix:()Ljava/lang/String;" (coverage
        :reachable (0 1)
      )
      :"jpamb.cases.advanced.Extended470.getNamespace:(I)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3 4)
      )
      :"jpamb.cases.advanced.Extended470.getSuffix:(Z)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3)
      )
      :"jpamb.cases.advanced.Extended470.indirect_construction_dispatcher:(Ljava/lang/String;II)V" (coverage
        :reachable (0 1 2 3 4 5 7 8 9 11 12 13 14 15 16 17 18 20 21 22 23 24 25 26 27 28 29)
      )
      :"jpamb.cases.advanced.Extended470.instantiate:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4)
      )
      :"jpamb.cases.advanced.Extended470.sanitizeInput:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3 6 7)
      )
      :"jpamb.cases.advanced.Extended470$__CANARY__Command.<init>:()V" (coverage
        :reachable (0 1 2)
      )
    )
    :results ("assertion error")
  )
  :"jpamb.cases.advanced.Extended470.multi_hop_dispatcher!(s'Safe')V" (control
    :coverage (
      :"jpamb.cases.advanced.Extended470.buildClassName:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3)
      )
      :"jpamb.cases.advanced.Extended470.classPrefix:()Ljava/lang/String;" (coverage
        :reachable (0 1)
      )
      :"jpamb.cases.advanced.Extended470.executeResolvedCommand:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2)
      )
      :"jpamb.cases.advanced.Extended470.instantiate:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4 6 7 8 9 12)
      )
      :"jpamb.cases.advanced.Extended470.multi_hop_dispatcher:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4 5 7 8 9 10 11 12)
      )
      :"jpamb.cases.advanced.Extended470.prepareCommand:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2)
      )
      :"jpamb.cases.advanced.Extended470.resolveCommand:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2)
      )
      :"jpamb.cases.advanced.Extended470.sanitizeInput:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3 6 7)
      )
      :"jpamb.cases.advanced.Extended470.weakValidation:(Ljava/lang/String;)Z" (coverage
        :reachable (0 1 2 3 4 5 6 7 8 9 10 11 13)
      )
      :"jpamb.cases.advanced.Extended470$SafeCommand.<init>:()V" (coverage
        :reachable (0 1 2)
      )
      :"jpamb.cases.advanced.Extended470$SafeCommand.doAction:()V" (coverage
        :reachable (0)
      )
    )
    :results (ok)
  )
  :"jpamb.cases.advanced.Extended470.multi_hop_dispatcher!(s'__CANARY__')V" (control
    :coverage (
      :"jpamb.cases.advanced.Extended470.buildClassName:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3)
      )
      :"jpamb.cases.advanced.Extended470.canary:()V" (coverage
        :reachable (0)
      )
      :"jpamb.cases.advanced.Extended470.classPrefix:()Ljava/lang/String;" (coverage
        :reachable (0 1)
      )
      :"jpamb.cases.advanced.Extended470.executeResolvedCommand:(Ljava/lang/String;)V" (coverage
        :reachable (0 1)
      )
      :"jpamb.cases.advanced.Extended470.instantiate:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4)
      )
      :"jpamb.cases.advanced.Extended470.multi_hop_dispatcher:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4 5 7 8 9 10 11)
      )
      :"jpamb.cases.advanced.Extended470.prepareCommand:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2)
      )
      :"jpamb.cases.advanced.Extended470.resolveCommand:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2)
      )
      :"jpamb.cases.advanced.Extended470.sanitizeInput:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3 6 7)
      )
      :"jpamb.cases.advanced.Extended470.weakValidation:(Ljava/lang/String;)Z" (coverage
        :reachable (0 1 2 3 4 5 6 7 8 9 10 11 13)
      )
      :"jpamb.cases.advanced.Extended470$__CANARY__Command.<init>:()V" (coverage
        :reachable (0 1 2)
      )
    )
    :results ("assertion error")
  )
  :"jpamb.cases.advanced.Extended470.multi_parameter_dispatcher!(s'Safe', s'production', s'admin', 1, 0)V" (control
    :coverage (
      :"jpamb.cases.advanced.Extended470.buildClassName:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3)
      )
      :"jpamb.cases.advanced.Extended470.classPrefix:()Ljava/lang/String;" (coverage
        :reachable (0 1)
      )
      :"jpamb.cases.advanced.Extended470.instantiate:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4 6 7 8 9 12)
      )
      :"jpamb.cases.advanced.Extended470.multi_parameter_dispatcher:(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;II)V" (coverage
        :reachable (0 1 2 4 5 6 7 9 10 11 12 14 15 17 18 19 20)
      )
      :"jpamb.cases.advanced.Extended470$SafeCommand.<init>:()V" (coverage
        :reachable (0 1 2)
      )
      :"jpamb.cases.advanced.Extended470$SafeCommand.doAction:()V" (coverage
        :reachable (0)
      )
    )
    :results (ok)
  )
  :"jpamb.cases.advanced.Extended470.multi_parameter_dispatcher!(s'__CANARY__', s'production', s'admin', 1, 0)V" (control
    :coverage (
      :"jpamb.cases.advanced.Extended470.buildClassName:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3)
      )
      :"jpamb.cases.advanced.Extended470.canary:()V" (coverage
        :reachable (0)
      )
      :"jpamb.cases.advanced.Extended470.classPrefix:()Ljava/lang/String;" (coverage
        :reachable (0 1)
      )
      :"jpamb.cases.advanced.Extended470.instantiate:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4)
      )
      :"jpamb.cases.advanced.Extended470.multi_parameter_dispatcher:(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;II)V" (coverage
        :reachable (0 1 2 4 5 6 7 9 10 11 12 14 15 17 18 19)
      )
      :"jpamb.cases.advanced.Extended470$__CANARY__Command.<init>:()V" (coverage
        :reachable (0 1 2)
      )
    )
    :results ("assertion error")
  )
  :"jpamb.cases.advanced.Extended470.object_propagation_dispatcher!(s'Safe', s'tenant1', s'production', s'execute')V" (control
    :coverage (
      :"jpamb.cases.advanced.Extended470.buildClassName:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3)
      )
      :"jpamb.cases.advanced.Extended470.classPrefix:()Ljava/lang/String;" (coverage
        :reachable (0 1)
      )
      :"jpamb.cases.advanced.Extended470.instantiate:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4 6 7 8 9 12)
      )
      :"jpamb.cases.advanced.Extended470.object_propagation_dispatcher:(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4 5)
      )
      :"jpamb.cases.advanced.Extended470.prepareRequest:(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3 6 7 8 9 12 13 14 17 18)
      )
      :"jpamb.cases.advanced.Extended470.processRequest:(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4 5 6 7 8 9)
      )
      :"jpamb.cases.advanced.Extended470$SafeCommand.<init>:()V" (coverage
        :reachable (0 1 2)
      )
      :"jpamb.cases.advanced.Extended470$SafeCommand.doAction:()V" (coverage
        :reachable (0)
      )
    )
    :results (ok)
  )
  :"jpamb.cases.advanced.Extended470.object_propagation_dispatcher!(s'__CANARY__', s'tenant1', s'production', s'execute')V" (control
    :coverage (
      :"jpamb.cases.advanced.Extended470.buildClassName:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3)
      )
      :"jpamb.cases.advanced.Extended470.canary:()V" (coverage
        :reachable (0)
      )
      :"jpamb.cases.advanced.Extended470.classPrefix:()Ljava/lang/String;" (coverage
        :reachable (0 1)
      )
      :"jpamb.cases.advanced.Extended470.instantiate:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4)
      )
      :"jpamb.cases.advanced.Extended470.object_propagation_dispatcher:(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4)
      )
      :"jpamb.cases.advanced.Extended470.prepareRequest:(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3 6 7 8 9 12 13 14 17 18)
      )
      :"jpamb.cases.advanced.Extended470.processRequest:(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4 5 6 7 8)
      )
      :"jpamb.cases.advanced.Extended470$__CANARY__Command.<init>:()V" (coverage
        :reachable (0 1 2)
      )
    )
    :results ("assertion error")
  )
  :"jpamb.cases.advanced.Extended470.prefix_dispatcher!(s'Safe')V" (control
    :coverage (
      :"jpamb.cases.advanced.Extended470.buildClassName:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3)
      )
      :"jpamb.cases.advanced.Extended470.classPrefix:()Ljava/lang/String;" (coverage
        :reachable (0 1)
      )
      :"jpamb.cases.advanced.Extended470.instantiate:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4 6 7 8 9 12)
      )
      :"jpamb.cases.advanced.Extended470.prefixValidation:(Ljava/lang/String;)Z" (coverage
        :reachable (0 1 2 3 4 5 6 7 9)
      )
      :"jpamb.cases.advanced.Extended470.prefix_dispatcher:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4 5 7 8 9 10 12 13 14 15)
      )
      :"jpamb.cases.advanced.Extended470.sanitizeInput:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3 6 7)
      )
      :"jpamb.cases.advanced.Extended470$SafeCommand.<init>:()V" (coverage
        :reachable (0 1 2)
      )
      :"jpamb.cases.advanced.Extended470$SafeCommand.doAction:()V" (coverage
        :reachable (0)
      )
    )
    :results (ok)
  )
  :"jpamb.cases.advanced.Extended470.prefix_dispatcher!(s'SafeWrapper')V" (control
    :coverage (
      :"jpamb.cases.advanced.Extended470.buildClassName:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3)
      )
      :"jpamb.cases.advanced.Extended470.canary:()V" (coverage
        :reachable (0)
      )
      :"jpamb.cases.advanced.Extended470.classPrefix:()Ljava/lang/String;" (coverage
        :reachable (0 1)
      )
      :"jpamb.cases.advanced.Extended470.instantiate:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4)
      )
      :"jpamb.cases.advanced.Extended470.prefixValidation:(Ljava/lang/String;)Z" (coverage
        :reachable (0 1 2 3 4 5 6 7 9)
      )
      :"jpamb.cases.advanced.Extended470.prefix_dispatcher:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4 5 7 8 9 10 12 13 14)
      )
      :"jpamb.cases.advanced.Extended470.sanitizeInput:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3 6 7)
      )
      :"jpamb.cases.advanced.Extended470$SafeWrapperCommand.<init>:()V" (coverage
        :reachable (0 1)
      )
      :"jpamb.cases.advanced.Extended470$__CANARY__Command.<init>:()V" (coverage
        :reachable (0 1 2)
      )
    )
    :results ("assertion error")
  )
  :"jpamb.cases.advanced.Extended470.regex_dispatcher!(s'Safe')V" (control
    :coverage (
      :"jpamb.cases.advanced.Extended470.buildClassName:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3)
      )
      :"jpamb.cases.advanced.Extended470.classPrefix:()Ljava/lang/String;" (coverage
        :reachable (0 1)
      )
      :"jpamb.cases.advanced.Extended470.instantiate:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4 6 7 8 9 12)
      )
      :"jpamb.cases.advanced.Extended470.regex_dispatcher:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 5 6 7 8 10 11 12 14 15 16 17)
      )
      :"jpamb.cases.advanced.Extended470$SafeCommand.<init>:()V" (coverage
        :reachable (0 1 2)
      )
      :"jpamb.cases.advanced.Extended470$SafeCommand.doAction:()V" (coverage
        :reachable (0)
      )
    )
    :results (ok)
  )
  :"jpamb.cases.advanced.Extended470.regex_dispatcher!(s'__CANARY__')V" (control
    :coverage (
      :"jpamb.cases.advanced.Extended470.buildClassName:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3)
      )
      :"jpamb.cases.advanced.Extended470.canary:()V" (coverage
        :reachable (0)
      )
      :"jpamb.cases.advanced.Extended470.classPrefix:()Ljava/lang/String;" (coverage
        :reachable (0 1)
      )
      :"jpamb.cases.advanced.Extended470.instantiate:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4)
      )
      :"jpamb.cases.advanced.Extended470.regex_dispatcher:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 5 6 7 8 10 11 12 14 15 16)
      )
      :"jpamb.cases.advanced.Extended470$__CANARY__Command.<init>:()V" (coverage
        :reachable (0 1 2)
      )
    )
    :results ("assertion error")
  )
  :"jpamb.cases.advanced.Extended470.sanitized_dispatcher!(s'Safe')V" (control
    :coverage (
      :"jpamb.cases.advanced.Extended470.buildClassName:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3)
      )
      :"jpamb.cases.advanced.Extended470.classPrefix:()Ljava/lang/String;" (coverage
        :reachable (0 1)
      )
      :"jpamb.cases.advanced.Extended470.instantiate:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4 6 7 8 9 12)
      )
      :"jpamb.cases.advanced.Extended470.sanitizeIdentifier:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3 6 7 8 9 12 13)
      )
      :"jpamb.cases.advanced.Extended470.sanitized_dispatcher:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4 5 7 8 9 10)
      )
      :"jpamb.cases.advanced.Extended470.weakValidation:(Ljava/lang/String;)Z" (coverage
        :reachable (0 1 2 3 4 5 6 7 8 9 10 11 13)
      )
      :"jpamb.cases.advanced.Extended470$SafeCommand.<init>:()V" (coverage
        :reachable (0 1 2)
      )
      :"jpamb.cases.advanced.Extended470$SafeCommand.doAction:()V" (coverage
        :reachable (0)
      )
    )
    :results (ok)
  )
  :"jpamb.cases.advanced.Extended470.sanitized_dispatcher!(s'__CANARY__')V" (control
    :coverage (
      :"jpamb.cases.advanced.Extended470.buildClassName:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3)
      )
      :"jpamb.cases.advanced.Extended470.canary:()V" (coverage
        :reachable (0)
      )
      :"jpamb.cases.advanced.Extended470.classPrefix:()Ljava/lang/String;" (coverage
        :reachable (0 1)
      )
      :"jpamb.cases.advanced.Extended470.instantiate:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4)
      )
      :"jpamb.cases.advanced.Extended470.sanitizeIdentifier:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3 6 7 8 9 12 13)
      )
      :"jpamb.cases.advanced.Extended470.sanitized_dispatcher:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4 5 7 8 9)
      )
      :"jpamb.cases.advanced.Extended470.weakValidation:(Ljava/lang/String;)Z" (coverage
        :reachable (0 1 2 3 4 5 6 7 8 9 10 11 13)
      )
      :"jpamb.cases.advanced.Extended470$__CANARY__Command.<init>:()V" (coverage
        :reachable (0 1 2)
      )
    )
    :results ("assertion error")
  )
  :"jpamb.cases.advanced.Extended470.strict_safe_dispatcher!(s'Any')V" (control
    :coverage (
      :"jpamb.cases.advanced.Extended470.strict_safe_dispatcher:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4)
      )
    )
    :results (ok)
  )
  :"jpamb.cases.advanced.Extended470.two_stage_validation_dispatcher!(s'Safe', s'admin', s'production', 1)V" (control
    :coverage (
      :"jpamb.cases.advanced.Extended470.buildClassName:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3)
      )
      :"jpamb.cases.advanced.Extended470.checkEnvironment:(Ljava/lang/String;)Z" (coverage
        :reachable (0 1 2 3 8 9 11)
      )
      :"jpamb.cases.advanced.Extended470.checkRole:(Ljava/lang/String;)Z" (coverage
        :reachable (0 1 2 3 4 5 6 7 8 9 11)
      )
      :"jpamb.cases.advanced.Extended470.classPrefix:()Ljava/lang/String;" (coverage
        :reachable (0 1)
      )
      :"jpamb.cases.advanced.Extended470.instantiate:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4 6 7 8 9 12)
      )
      :"jpamb.cases.advanced.Extended470.normalizePath:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3 6 7)
      )
      :"jpamb.cases.advanced.Extended470.two_stage_validation_dispatcher:(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)V" (coverage
        :reachable (0 1 2 4 5 6 8 9 10 12 13 14 15 16 17 19 20 21 22)
      )
      :"jpamb.cases.advanced.Extended470.weakValidation:(Ljava/lang/String;)Z" (coverage
        :reachable (0 1 2 3 4 5 6 7 8 9 10 11 13)
      )
      :"jpamb.cases.advanced.Extended470$SafeCommand.<init>:()V" (coverage
        :reachable (0 1 2)
      )
      :"jpamb.cases.advanced.Extended470$SafeCommand.doAction:()V" (coverage
        :reachable (0)
      )
    )
    :results (ok)
  )
  :"jpamb.cases.advanced.Extended470.two_stage_validation_dispatcher!(s'__CANARY__', s'admin', s'production', 1)V" (control
    :coverage (
      :"jpamb.cases.advanced.Extended470.buildClassName:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3)
      )
      :"jpamb.cases.advanced.Extended470.canary:()V" (coverage
        :reachable (0)
      )
      :"jpamb.cases.advanced.Extended470.checkEnvironment:(Ljava/lang/String;)Z" (coverage
        :reachable (0 1 2 3 8 9 11)
      )
      :"jpamb.cases.advanced.Extended470.checkRole:(Ljava/lang/String;)Z" (coverage
        :reachable (0 1 2 3 4 5 6 7 8 9 11)
      )
      :"jpamb.cases.advanced.Extended470.classPrefix:()Ljava/lang/String;" (coverage
        :reachable (0 1)
      )
      :"jpamb.cases.advanced.Extended470.instantiate:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4)
      )
      :"jpamb.cases.advanced.Extended470.normalizePath:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3 6 7)
      )
      :"jpamb.cases.advanced.Extended470.two_stage_validation_dispatcher:(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)V" (coverage
        :reachable (0 1 2 4 5 6 8 9 10 12 13 14 15 16 17 19 20 21)
      )
      :"jpamb.cases.advanced.Extended470.weakValidation:(Ljava/lang/String;)Z" (coverage
        :reachable (0 1 2 3 4 5 6 7 8 9 10 11 13)
      )
      :"jpamb.cases.advanced.Extended470$__CANARY__Command.<init>:()V" (coverage
        :reachable (0 1 2)
      )
    )
    :results ("assertion error")
  )
  :"jpamb.cases.advanced.Extended470.two_step_dispatcher!(s'Any', 0)V" (control
    :coverage (
      :"jpamb.cases.advanced.Extended470.two_step_dispatcher:(Ljava/lang/String;I)V" (coverage
        :reachable (0 1 2)
      )
    )
    :results (ok)
  )
  :"jpamb.cases.advanced.Extended470.two_step_dispatcher!(s'__CANARY__', 1)V" (control
    :coverage (
      :"jpamb.cases.advanced.Extended470.buildClassName:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3)
      )
      :"jpamb.cases.advanced.Extended470.canary:()V" (coverage
        :reachable (0)
      )
      :"jpamb.cases.advanced.Extended470.classPrefix:()Ljava/lang/String;" (coverage
        :reachable (0 1)
      )
      :"jpamb.cases.advanced.Extended470.instantiate:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4)
      )
      :"jpamb.cases.advanced.Extended470.two_step_dispatcher:(Ljava/lang/String;I)V" (coverage
        :reachable (0 1 3 4)
      )
      :"jpamb.cases.advanced.Extended470.unsafe_dispatcher:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4)
      )
      :"jpamb.cases.advanced.Extended470$__CANARY__Command.<init>:()V" (coverage
        :reachable (0 1 2)
      )
    )
    :results ("assertion error")
  )
  :"jpamb.cases.advanced.Extended470.unsafe_dispatcher!(s'Safe')V" (control
    :coverage (
      :"jpamb.cases.advanced.Extended470.buildClassName:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3)
      )
      :"jpamb.cases.advanced.Extended470.classPrefix:()Ljava/lang/String;" (coverage
        :reachable (0 1)
      )
      :"jpamb.cases.advanced.Extended470.instantiate:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4 6 7 8 9 12)
      )
      :"jpamb.cases.advanced.Extended470.unsafe_dispatcher:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4 5)
      )
      :"jpamb.cases.advanced.Extended470$SafeCommand.<init>:()V" (coverage
        :reachable (0 1 2)
      )
      :"jpamb.cases.advanced.Extended470$SafeCommand.doAction:()V" (coverage
        :reachable (0)
      )
    )
    :results (ok)
  )
  :"jpamb.cases.advanced.Extended470.unsafe_dispatcher!(s'__CANARY__')V" (control
    :coverage (
      :"jpamb.cases.advanced.Extended470.buildClassName:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3)
      )
      :"jpamb.cases.advanced.Extended470.canary:()V" (coverage
        :reachable (0)
      )
      :"jpamb.cases.advanced.Extended470.classPrefix:()Ljava/lang/String;" (coverage
        :reachable (0 1)
      )
      :"jpamb.cases.advanced.Extended470.instantiate:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4)
      )
      :"jpamb.cases.advanced.Extended470.unsafe_dispatcher:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4)
      )
      :"jpamb.cases.advanced.Extended470$__CANARY__Command.<init>:()V" (coverage
        :reachable (0 1 2)
      )
    )
    :results ("assertion error")
  )
  :"jpamb.cases.advanced.Extended470.weak_dispatcher!(s'Safe')V" (control
    :coverage (
      :"jpamb.cases.advanced.Extended470.buildClassName:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3)
      )
      :"jpamb.cases.advanced.Extended470.classPrefix:()Ljava/lang/String;" (coverage
        :reachable (0 1)
      )
      :"jpamb.cases.advanced.Extended470.instantiate:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4 6 7 8 9 12)
      )
      :"jpamb.cases.advanced.Extended470.weak_dispatcher:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 5 6 7 8)
      )
      :"jpamb.cases.advanced.Extended470$SafeCommand.<init>:()V" (coverage
        :reachable (0 1 2)
      )
      :"jpamb.cases.advanced.Extended470$SafeCommand.doAction:()V" (coverage
        :reachable (0)
      )
    )
    :results (ok)
  )
  :"jpamb.cases.advanced.Extended470.weak_dispatcher!(s'SafeWrapper')V" (control
    :coverage (
      :"jpamb.cases.advanced.Extended470.buildClassName:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3)
      )
      :"jpamb.cases.advanced.Extended470.canary:()V" (coverage
        :reachable (0)
      )
      :"jpamb.cases.advanced.Extended470.classPrefix:()Ljava/lang/String;" (coverage
        :reachable (0 1)
      )
      :"jpamb.cases.advanced.Extended470.instantiate:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4)
      )
      :"jpamb.cases.advanced.Extended470.weak_dispatcher:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 5 6 7)
      )
      :"jpamb.cases.advanced.Extended470$SafeWrapperCommand.<init>:()V" (coverage
        :reachable (0 1)
      )
      :"jpamb.cases.advanced.Extended470$__CANARY__Command.<init>:()V" (coverage
        :reachable (0 1 2)
      )
    )
    :results ("assertion error")
  )
  :"jpamb.cases.advanced.Extended470.alias_dispatcher:(Ljava/lang/String;)V" (control
    :coverage (
      :"jpamb.cases.advanced.Extended470.alias_dispatcher:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4 5 7 8 9 10)
      )
      :"jpamb.cases.advanced.Extended470.buildClassName:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3)
      )
      :"jpamb.cases.advanced.Extended470.canary:()V" (coverage
        :reachable (0)
      )
      :"jpamb.cases.advanced.Extended470.classPrefix:()Ljava/lang/String;" (coverage
        :reachable (0 1)
      )
      :"jpamb.cases.advanced.Extended470.instantiate:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4 6 7 8 9 12)
      )
      :"jpamb.cases.advanced.Extended470.resolveAlias:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3 4 5 6 7 8 9 12 13 14 15 18 19)
      )
      :"jpamb.cases.advanced.Extended470.weakValidation:(Ljava/lang/String;)Z" (coverage
        :reachable (0 1 2 3 4 5 6 7 8 9 10 11 13)
      )
      :"jpamb.cases.advanced.Extended470$__CANARY__Command.<init>:()V" (coverage
        :reachable (0 1 2)
      )
      :"jpamb.cases.advanced.Extended470$ExportCommand.<init>:()V" (coverage
        :reachable (0 1 2)
      )
      :"jpamb.cases.advanced.Extended470$SafeCommand.<init>:()V" (coverage
        :reachable (0 1 2)
      )
      :"jpamb.cases.advanced.Extended470$SafeCommand.doAction:()V" (coverage
        :reachable (0)
      )
    )
    :results ("assertion error" ok)
  )
  :"jpamb.cases.advanced.Extended470.allowlist_dispatcher:(Ljava/lang/String;)V" (control
    :coverage (
      :"jpamb.cases.advanced.Extended470.allowlist_dispatcher:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 3 4 5 6 7 8 9 10)
      )
      :"jpamb.cases.advanced.Extended470.buildClassName:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3)
      )
      :"jpamb.cases.advanced.Extended470.classPrefix:()Ljava/lang/String;" (coverage
        :reachable (0 1)
      )
      :"jpamb.cases.advanced.Extended470.instantiate:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4 6 7 8 9 12)
      )
      :"jpamb.cases.advanced.Extended470.isAllowed:(Ljava/lang/String;)Z" (coverage
        :reachable (0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23)
      )
      :"jpamb.cases.advanced.Extended470$SafeCommand.<init>:()V" (coverage
        :reachable (0 1 2)
      )
      :"jpamb.cases.advanced.Extended470$SafeCommand.doAction:()V" (coverage
        :reachable (0)
      )
    )
    :results (ok)
  )
  :"jpamb.cases.advanced.Extended470.chained_sanitization_dispatcher:(Ljava/lang/String;)V" (control
    :coverage (
      :"jpamb.cases.advanced.Extended470.buildClassName:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3)
      )
      :"jpamb.cases.advanced.Extended470.chained_sanitization_dispatcher:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 16 17 18 19)
      )
      :"jpamb.cases.advanced.Extended470.classPrefix:()Ljava/lang/String;" (coverage
        :reachable (0 1)
      )
      :"jpamb.cases.advanced.Extended470.firstSanitization:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3 6 7)
      )
      :"jpamb.cases.advanced.Extended470.instantiate:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4 6 7 8 9 12)
      )
      :"jpamb.cases.advanced.Extended470.sanitizeIdentifier:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3 6 7 8 9 12 13)
      )
      :"jpamb.cases.advanced.Extended470.secondSanitization:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3 6 7)
      )
      :"jpamb.cases.advanced.Extended470.thirdSanitization:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3 6 7)
      )
      :"jpamb.cases.advanced.Extended470.weakValidation:(Ljava/lang/String;)Z" (coverage
        :reachable (0 1 2 3 4 5 6 7 8 9 10 11 13)
      )
      :"jpamb.cases.advanced.Extended470$SafeCommand.<init>:()V" (coverage
        :reachable (0 1 2)
      )
      :"jpamb.cases.advanced.Extended470$SafeCommand.doAction:()V" (coverage
        :reachable (0)
      )
      :"jpamb.cases.advanced.Extended470.canary:()V" (coverage
        :reachable (0)
      )
      :"jpamb.cases.advanced.Extended470$__CANARY__Command.<init>:()V" (coverage
        :reachable (0 1 2)
      )
    )
    :results ("assertion error" ok)
  )
  :"jpamb.cases.advanced.Extended470.conditional_dispatcher:(Ljava/lang/String;III)V" (control
    :coverage (
      :"jpamb.cases.advanced.Extended470.buildClassName:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3)
      )
      :"jpamb.cases.advanced.Extended470.checkFeatureFlag:(I)Z" (coverage
        :reachable (0 1 2 3 4 6)
      )
      :"jpamb.cases.advanced.Extended470.checkPermission:(I)Z" (coverage
        :reachable (0 1 2 3 4 5 6 8)
      )
      :"jpamb.cases.advanced.Extended470.classPrefix:()Ljava/lang/String;" (coverage
        :reachable (0 1)
      )
      :"jpamb.cases.advanced.Extended470.conditional_dispatcher:(Ljava/lang/String;III)V" (coverage
        :reachable (0 1 2 4 5 6 8 9 10 12 13 14 15 16 17 18 20 21 22 23)
      )
      :"jpamb.cases.advanced.Extended470.instantiate:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4 6 7 8 9 12)
      )
      :"jpamb.cases.advanced.Extended470.sanitizeInput:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3 6 7)
      )
      :"jpamb.cases.advanced.Extended470$SafeCommand.<init>:()V" (coverage
        :reachable (0 1 2)
      )
      :"jpamb.cases.advanced.Extended470$SafeCommand.doAction:()V" (coverage
        :reachable (0)
      )
      :"jpamb.cases.advanced.Extended470.canary:()V" (coverage
        :reachable (0)
      )
      :"jpamb.cases.advanced.Extended470$__CANARY__Command.<init>:()V" (coverage
        :reachable (0 1 2)
      )
    )
    :results ("assertion error" ok)
  )
  :"jpamb.cases.advanced.Extended470.deep_chain_dispatcher:(Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;ILjava/lang/String;I)V" (control
    :coverage (
      :"jpamb.cases.advanced.Extended470.buildClassName:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3)
      )
      :"jpamb.cases.advanced.Extended470.classPrefix:()Ljava/lang/String;" (coverage
        :reachable (0 1)
      )
      :"jpamb.cases.advanced.Extended470.deep_chain_dispatcher:(Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;ILjava/lang/String;I)V" (coverage
        :reachable (0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19)
      )
      :"jpamb.cases.advanced.Extended470.instantiate:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4 6 7 8 9 12)
      )
      :"jpamb.cases.advanced.Extended470.stageFour:(Ljava/lang/String;Ljava/lang/String;I)V" (coverage
        :reachable (0 1 2 4 5 6 8 9 10)
      )
      :"jpamb.cases.advanced.Extended470.stageOne:(Ljava/lang/String;Ljava/lang/String;I)Ljava/lang/String;" (coverage
        :reachable (0 1 2 5 6 7 10 11)
      )
      :"jpamb.cases.advanced.Extended470.stageThree:(Ljava/lang/String;IZ)Ljava/lang/String;" (coverage
        :reachable (0 1 4 5 6 9 10 11)
      )
      :"jpamb.cases.advanced.Extended470.stageTwo:(Ljava/lang/String;Ljava/lang/String;Z)Ljava/lang/String;" (coverage
        :reachable (0 1 4 5 6 7 10 11)
      )
      :"jpamb.cases.advanced.Extended470$SafeCommand.<init>:()V" (coverage
        :reachable (0 1 2)
      )
      :"jpamb.cases.advanced.Extended470$SafeCommand.doAction:()V" (coverage
        :reachable (0)
      )
      :"jpamb.cases.advanced.Extended470.canary:()V" (coverage
        :reachable (0)
      )
      :"jpamb.cases.advanced.Extended470$__CANARY__Command.<init>:()V" (coverage
        :reachable (0 1 2)
      )
    )
    :results ("assertion error" ok)
  )
  :"jpamb.cases.advanced.Extended470.fallback_dispatcher:(Ljava/lang/String;)V" (control
    :coverage (
      :"jpamb.cases.advanced.Extended470.buildClassName:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3)
      )
      :"jpamb.cases.advanced.Extended470.classPrefix:()Ljava/lang/String;" (coverage
        :reachable (0 1)
      )
      :"jpamb.cases.advanced.Extended470.fallback_dispatcher:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4 5 7 8 9 10)
      )
      :"jpamb.cases.advanced.Extended470.instantiate:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4 6 7 8 9 12)
      )
      :"jpamb.cases.advanced.Extended470.isKnownCommand:(Ljava/lang/String;)Z" (coverage
        :reachable (0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15)
      )
      :"jpamb.cases.advanced.Extended470.validateOrFallback:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3 4 5 6 7)
      )
      :"jpamb.cases.advanced.Extended470.weakValidation:(Ljava/lang/String;)Z" (coverage
        :reachable (0 1 2 3 4 5 6 7 8 9 10 11 13)
      )
      :"jpamb.cases.advanced.Extended470$SafeCommand.<init>:()V" (coverage
        :reachable (0 1 2)
      )
      :"jpamb.cases.advanced.Extended470$SafeCommand.doAction:()V" (coverage
        :reachable (0)
      )
      :"jpamb.cases.advanced.Extended470.canary:()V" (coverage
        :reachable (0)
      )
      :"jpamb.cases.advanced.Extended470.sanitizeIdentifier:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3 6 7 8 9 12 13)
      )
      :"jpamb.cases.advanced.Extended470$__CANARY__Command.<init>:()V" (coverage
        :reachable (0 1 2)
      )
    )
    :results ("assertion error" ok)
  )
  :"jpamb.cases.advanced.Extended470.indirect_construction_dispatcher:(Ljava/lang/String;II)V" (control
    :coverage (
      :"jpamb.cases.advanced.Extended470.classPrefix:()Ljava/lang/String;" (coverage
        :reachable (0 1)
      )
      :"jpamb.cases.advanced.Extended470.getNamespace:(I)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3 4)
      )
      :"jpamb.cases.advanced.Extended470.getSuffix:(Z)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3)
      )
      :"jpamb.cases.advanced.Extended470.indirect_construction_dispatcher:(Ljava/lang/String;II)V" (coverage
        :reachable (0 1 2 3 4 5 7 8 9 11 12 13 14 15 16 17 18 20 21 22 23 24 25 26 27 28 29 30)
      )
      :"jpamb.cases.advanced.Extended470.instantiate:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4 6 7 8 9 12)
      )
      :"jpamb.cases.advanced.Extended470.sanitizeInput:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3 6 7)
      )
      :"jpamb.cases.advanced.Extended470$SafeCommand.<init>:()V" (coverage
        :reachable (0 1 2)
      )
      :"jpamb.cases.advanced.Extended470$SafeCommand.doAction:()V" (coverage
        :reachable (0)
      )
      :"jpamb.cases.advanced.Extended470.canary:()V" (coverage
        :reachable (0)
      )
      :"jpamb.cases.advanced.Extended470$__CANARY__Command.<init>:()V" (coverage
        :reachable (0 1 2)
      )
    )
    :results ("assertion error" ok)
  )
  :"jpamb.cases.advanced.Extended470.multi_hop_dispatcher:(Ljava/lang/String;)V" (control
    :coverage (
      :"jpamb.cases.advanced.Extended470.buildClassName:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3)
      )
      :"jpamb.cases.advanced.Extended470.classPrefix:()Ljava/lang/String;" (coverage
        :reachable (0 1)
      )
      :"jpamb.cases.advanced.Extended470.executeResolvedCommand:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2)
      )
      :"jpamb.cases.advanced.Extended470.instantiate:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4 6 7 8 9 12)
      )
      :"jpamb.cases.advanced.Extended470.multi_hop_dispatcher:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4 5 7 8 9 10 11 12)
      )
      :"jpamb.cases.advanced.Extended470.prepareCommand:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2)
      )
      :"jpamb.cases.advanced.Extended470.resolveCommand:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2)
      )
      :"jpamb.cases.advanced.Extended470.sanitizeInput:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3 6 7)
      )
      :"jpamb.cases.advanced.Extended470.weakValidation:(Ljava/lang/String;)Z" (coverage
        :reachable (0 1 2 3 4 5 6 7 8 9 10 11 13)
      )
      :"jpamb.cases.advanced.Extended470$SafeCommand.<init>:()V" (coverage
        :reachable (0 1 2)
      )
      :"jpamb.cases.advanced.Extended470$SafeCommand.doAction:()V" (coverage
        :reachable (0)
      )
      :"jpamb.cases.advanced.Extended470.canary:()V" (coverage
        :reachable (0)
      )
      :"jpamb.cases.advanced.Extended470$__CANARY__Command.<init>:()V" (coverage
        :reachable (0 1 2)
      )
    )
    :results ("assertion error" ok)
  )
  :"jpamb.cases.advanced.Extended470.multi_parameter_dispatcher:(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;II)V" (control
    :coverage (
      :"jpamb.cases.advanced.Extended470.buildClassName:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3)
      )
      :"jpamb.cases.advanced.Extended470.classPrefix:()Ljava/lang/String;" (coverage
        :reachable (0 1)
      )
      :"jpamb.cases.advanced.Extended470.instantiate:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4 6 7 8 9 12)
      )
      :"jpamb.cases.advanced.Extended470.multi_parameter_dispatcher:(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;II)V" (coverage
        :reachable (0 1 2 4 5 6 7 9 10 11 12 14 15 17 18 19 20)
      )
      :"jpamb.cases.advanced.Extended470$SafeCommand.<init>:()V" (coverage
        :reachable (0 1 2)
      )
      :"jpamb.cases.advanced.Extended470$SafeCommand.doAction:()V" (coverage
        :reachable (0)
      )
      :"jpamb.cases.advanced.Extended470.canary:()V" (coverage
        :reachable (0)
      )
      :"jpamb.cases.advanced.Extended470$__CANARY__Command.<init>:()V" (coverage
        :reachable (0 1 2)
      )
    )
    :results ("assertion error" ok)
  )
  :"jpamb.cases.advanced.Extended470.object_propagation_dispatcher:(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V" (control
    :coverage (
      :"jpamb.cases.advanced.Extended470.buildClassName:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3)
      )
      :"jpamb.cases.advanced.Extended470.classPrefix:()Ljava/lang/String;" (coverage
        :reachable (0 1)
      )
      :"jpamb.cases.advanced.Extended470.instantiate:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4 6 7 8 9 12)
      )
      :"jpamb.cases.advanced.Extended470.object_propagation_dispatcher:(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4 5)
      )
      :"jpamb.cases.advanced.Extended470.prepareRequest:(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3 6 7 8 9 12 13 14 17 18)
      )
      :"jpamb.cases.advanced.Extended470.processRequest:(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4 5 6 7 8 9)
      )
      :"jpamb.cases.advanced.Extended470$SafeCommand.<init>:()V" (coverage
        :reachable (0 1 2)
      )
      :"jpamb.cases.advanced.Extended470$SafeCommand.doAction:()V" (coverage
        :reachable (0)
      )
      :"jpamb.cases.advanced.Extended470.canary:()V" (coverage
        :reachable (0)
      )
      :"jpamb.cases.advanced.Extended470$__CANARY__Command.<init>:()V" (coverage
        :reachable (0 1 2)
      )
    )
    :results ("assertion error" ok)
  )
  :"jpamb.cases.advanced.Extended470.prefix_dispatcher:(Ljava/lang/String;)V" (control
    :coverage (
      :"jpamb.cases.advanced.Extended470.buildClassName:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3)
      )
      :"jpamb.cases.advanced.Extended470.classPrefix:()Ljava/lang/String;" (coverage
        :reachable (0 1)
      )
      :"jpamb.cases.advanced.Extended470.instantiate:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4 6 7 8 9 12)
      )
      :"jpamb.cases.advanced.Extended470.prefixValidation:(Ljava/lang/String;)Z" (coverage
        :reachable (0 1 2 3 4 5 6 7 9)
      )
      :"jpamb.cases.advanced.Extended470.prefix_dispatcher:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4 5 7 8 9 10 12 13 14 15)
      )
      :"jpamb.cases.advanced.Extended470.sanitizeInput:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3 6 7)
      )
      :"jpamb.cases.advanced.Extended470$SafeCommand.<init>:()V" (coverage
        :reachable (0 1 2)
      )
      :"jpamb.cases.advanced.Extended470$SafeCommand.doAction:()V" (coverage
        :reachable (0)
      )
      :"jpamb.cases.advanced.Extended470.canary:()V" (coverage
        :reachable (0)
      )
      :"jpamb.cases.advanced.Extended470$SafeWrapperCommand.<init>:()V" (coverage
        :reachable (0 1)
      )
      :"jpamb.cases.advanced.Extended470$__CANARY__Command.<init>:()V" (coverage
        :reachable (0 1 2)
      )
    )
    :results ("assertion error" ok)
  )
  :"jpamb.cases.advanced.Extended470.regex_dispatcher:(Ljava/lang/String;)V" (control
    :coverage (
      :"jpamb.cases.advanced.Extended470.buildClassName:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3)
      )
      :"jpamb.cases.advanced.Extended470.classPrefix:()Ljava/lang/String;" (coverage
        :reachable (0 1)
      )
      :"jpamb.cases.advanced.Extended470.instantiate:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4 6 7 8 9 12)
      )
      :"jpamb.cases.advanced.Extended470.regex_dispatcher:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 5 6 7 8 10 11 12 14 15 16 17)
      )
      :"jpamb.cases.advanced.Extended470$SafeCommand.<init>:()V" (coverage
        :reachable (0 1 2)
      )
      :"jpamb.cases.advanced.Extended470$SafeCommand.doAction:()V" (coverage
        :reachable (0)
      )
      :"jpamb.cases.advanced.Extended470.canary:()V" (coverage
        :reachable (0)
      )
      :"jpamb.cases.advanced.Extended470$__CANARY__Command.<init>:()V" (coverage
        :reachable (0 1 2)
      )
    )
    :results ("assertion error" ok)
  )
  :"jpamb.cases.advanced.Extended470.sanitized_dispatcher:(Ljava/lang/String;)V" (control
    :coverage (
      :"jpamb.cases.advanced.Extended470.buildClassName:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3)
      )
      :"jpamb.cases.advanced.Extended470.classPrefix:()Ljava/lang/String;" (coverage
        :reachable (0 1)
      )
      :"jpamb.cases.advanced.Extended470.instantiate:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4 6 7 8 9 12)
      )
      :"jpamb.cases.advanced.Extended470.sanitizeIdentifier:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3 6 7 8 9 12 13)
      )
      :"jpamb.cases.advanced.Extended470.sanitized_dispatcher:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4 5 7 8 9 10)
      )
      :"jpamb.cases.advanced.Extended470.weakValidation:(Ljava/lang/String;)Z" (coverage
        :reachable (0 1 2 3 4 5 6 7 8 9 10 11 13)
      )
      :"jpamb.cases.advanced.Extended470$SafeCommand.<init>:()V" (coverage
        :reachable (0 1 2)
      )
      :"jpamb.cases.advanced.Extended470$SafeCommand.doAction:()V" (coverage
        :reachable (0)
      )
      :"jpamb.cases.advanced.Extended470.canary:()V" (coverage
        :reachable (0)
      )
      :"jpamb.cases.advanced.Extended470$__CANARY__Command.<init>:()V" (coverage
        :reachable (0 1 2)
      )
    )
    :results ("assertion error" ok)
  )
  :"jpamb.cases.advanced.Extended470.strict_safe_dispatcher:(Ljava/lang/String;)V" (control
    :coverage (
      :"jpamb.cases.advanced.Extended470.strict_safe_dispatcher:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4)
      )
    )
    :results (ok)
  )
  :"jpamb.cases.advanced.Extended470.two_stage_validation_dispatcher:(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)V" (control
    :coverage (
      :"jpamb.cases.advanced.Extended470.buildClassName:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3)
      )
      :"jpamb.cases.advanced.Extended470.checkEnvironment:(Ljava/lang/String;)Z" (coverage
        :reachable (0 1 2 3 8 9 11)
      )
      :"jpamb.cases.advanced.Extended470.checkRole:(Ljava/lang/String;)Z" (coverage
        :reachable (0 1 2 3 4 5 6 7 8 9 11)
      )
      :"jpamb.cases.advanced.Extended470.classPrefix:()Ljava/lang/String;" (coverage
        :reachable (0 1)
      )
      :"jpamb.cases.advanced.Extended470.instantiate:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4 6 7 8 9 12)
      )
      :"jpamb.cases.advanced.Extended470.normalizePath:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3 6 7)
      )
      :"jpamb.cases.advanced.Extended470.two_stage_validation_dispatcher:(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)V" (coverage
        :reachable (0 1 2 4 5 6 8 9 10 12 13 14 15 16 17 19 20 21 22)
      )
      :"jpamb.cases.advanced.Extended470.weakValidation:(Ljava/lang/String;)Z" (coverage
        :reachable (0 1 2 3 4 5 6 7 8 9 10 11 13)
      )
      :"jpamb.cases.advanced.Extended470$SafeCommand.<init>:()V" (coverage
        :reachable (0 1 2)
      )
      :"jpamb.cases.advanced.Extended470$SafeCommand.doAction:()V" (coverage
        :reachable (0)
      )
      :"jpamb.cases.advanced.Extended470.canary:()V" (coverage
        :reachable (0)
      )
      :"jpamb.cases.advanced.Extended470$__CANARY__Command.<init>:()V" (coverage
        :reachable (0 1 2)
      )
    )
    :results ("assertion error" ok)
  )
  :"jpamb.cases.advanced.Extended470.two_step_dispatcher:(Ljava/lang/String;I)V" (control
    :coverage (
      :"jpamb.cases.advanced.Extended470.two_step_dispatcher:(Ljava/lang/String;I)V" (coverage
        :reachable (0 1 2 3 4)
      )
      :"jpamb.cases.advanced.Extended470.buildClassName:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3)
      )
      :"jpamb.cases.advanced.Extended470.canary:()V" (coverage
        :reachable (0)
      )
      :"jpamb.cases.advanced.Extended470.classPrefix:()Ljava/lang/String;" (coverage
        :reachable (0 1)
      )
      :"jpamb.cases.advanced.Extended470.instantiate:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4)
      )
      :"jpamb.cases.advanced.Extended470.unsafe_dispatcher:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4)
      )
      :"jpamb.cases.advanced.Extended470$__CANARY__Command.<init>:()V" (coverage
        :reachable (0 1 2)
      )
    )
    :results ("assertion error" ok)
  )
  :"jpamb.cases.advanced.Extended470.unsafe_dispatcher:(Ljava/lang/String;)V" (control
    :coverage (
      :"jpamb.cases.advanced.Extended470.buildClassName:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3)
      )
      :"jpamb.cases.advanced.Extended470.classPrefix:()Ljava/lang/String;" (coverage
        :reachable (0 1)
      )
      :"jpamb.cases.advanced.Extended470.instantiate:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4 6 7 8 9 12)
      )
      :"jpamb.cases.advanced.Extended470.unsafe_dispatcher:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4 5)
      )
      :"jpamb.cases.advanced.Extended470$SafeCommand.<init>:()V" (coverage
        :reachable (0 1 2)
      )
      :"jpamb.cases.advanced.Extended470$SafeCommand.doAction:()V" (coverage
        :reachable (0)
      )
      :"jpamb.cases.advanced.Extended470.canary:()V" (coverage
        :reachable (0)
      )
      :"jpamb.cases.advanced.Extended470$__CANARY__Command.<init>:()V" (coverage
        :reachable (0 1 2)
      )
    )
    :results ("assertion error" ok)
  )
  :"jpamb.cases.advanced.Extended470.weak_dispatcher:(Ljava/lang/String;)V" (control
    :coverage (
      :"jpamb.cases.advanced.Extended470.buildClassName:(Ljava/lang/String;)Ljava/lang/String;" (coverage
        :reachable (0 1 2 3)
      )
      :"jpamb.cases.advanced.Extended470.classPrefix:()Ljava/lang/String;" (coverage
        :reachable (0 1)
      )
      :"jpamb.cases.advanced.Extended470.instantiate:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 4 6 7 8 9 12)
      )
      :"jpamb.cases.advanced.Extended470.weak_dispatcher:(Ljava/lang/String;)V" (coverage
        :reachable (0 1 2 3 5 6 7 8)
      )
      :"jpamb.cases.advanced.Extended470$SafeCommand.<init>:()V" (coverage
        :reachable (0 1 2)
      )
      :"jpamb.cases.advanced.Extended470$SafeCommand.doAction:()V" (coverage
        :reachable (0)
      )
      :"jpamb.cases.advanced.Extended470.canary:()V" (coverage
        :reachable (0)
      )
      :"jpamb.cases.advanced.Extended470$SafeWrapperCommand.<init>:()V" (coverage
        :reachable (0 1)
      )
      :"jpamb.cases.advanced.Extended470$__CANARY__Command.<init>:()V" (coverage
        :reachable (0 1 2)
      )
    )
    :results ("assertion error" ok)
  )
)