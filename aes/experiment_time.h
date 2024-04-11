#if defined(msp432p401r) || defined(msp430g2553) || defined(msp430f5529)
unsigned long long int ticks = 0;
#endif

#if defined(msp430fr5994)
unsigned long int ticks = 0;
#endif

#ifdef msp432p401r
void SysTick_Handler(void) {
    ticks++;
}

#define startTimer() MAP_SysTick_setPeriod(300);    /* 1ms resolution */ \
                     MAP_SysTick_enableInterrupt();                       \
                     /* Enabling MASTER interrupts */                     \
                     MAP_Interrupt_enableMaster();                        \
                     MAP_SysTick_enableModule();   /* Start timer */      \
                     unsigned long long int start = ticks;
#endif

#if defined(msp430fr5994)
// Timer A0 interrupt service routine
#pragma vector=TIMER0_A0_VECTOR
__interrupt void TimeA0 (void)
{
  ticks++;
}

#define startTimer() TA0CCTL0 = CCIE;                 /* CCR0 interrupt enabled */    \
                     TA0CTL = TASSEL_2 + MC_1 + ID_3; /* SMCLK/8 (1 MHz/8), upmode */ \
                     TA0CCR0 =  128;                  /* 1 KHz */                     \
                     __bis_SR_register(GIE);         /* Enable all interrupts */     \
                     unsigned long int start = ticks;
#endif

#if defined(msp430g2553) || defined(msp430f5529)
// Timer A0 interrupt service routine
#pragma vector=TIMER0_A0_VECTOR
__interrupt void TimeA0 (void)
{
  ticks++;
}

#define startTimer() TA0CCTL0 = CCIE;                 /* CCR0 interrupt enabled */    \
                     TA0CTL = TASSEL_2 + MC_1 + ID_3; /* SMCLK/8 (1 MHz/8), upmode */ \
                     TA0CCR0 =  128;                  /* 1 KHz */                     \
                     __bis_SR_register(GIE);         /* Enable all interrupts */     \
                     unsigned long long int start = ticks;
#endif

#define getElapsedTime() (ticks - start)
