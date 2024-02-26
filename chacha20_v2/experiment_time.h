unsigned int ticks_s = 0;
unsigned int ticks_ms = 0;

#ifdef msp432p401r
void SysTick_Handler(void) {
    ticks_ms++;
}

#define startTimer() MAP_SysTick_setPeriod(300);    /* 1ms resolution */ \
                     MAP_SysTick_enableInterrupt();                       \
                     /* Enabling MASTER interrupts */                     \
                     MAP_Interrupt_enableMaster();                        \
                     MAP_SysTick_enableModule();   /* Start timer */      \
                     unsigned int start = ticks;
#endif

// Timer A0 interrupt service routine
#pragma vector=TIMER1_A0_VECTOR
__interrupt void TimeA1 (void)
{
  ticks_ms++;
  if (ticks_ms == 1000)
  {
      ticks_s++;
      ticks_ms = 0;
  }
}

#define startTimer() TA1CCTL0 = CCIE;                 /* CCR0 interrupt enabled */    \
                     TA1CTL = TASSEL_2 + MC_1 + ID_3; /* SMCLK/8 (1 MHz/8), upmode */ \
                     TA1CCR0 =  128;                  /* 1 KHz */                     \
                     __bis_SR_register(GIE);         /* Enable all interrupts */     \
                     unsigned int start = ticks_s;

#define getElapsedTime() (ticks_s - start)
