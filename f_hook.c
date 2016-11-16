#include "fhook.h"

static int init_hooks_x86(void)
{
	khookstr_t * s;

	khook_for_each(s) {
		s->target = get_symbol_address(s->name); // get address of symbol by func. name
		if (s->target) {
			s->target_map = map_writable(s->target, 32); // using tmp map method
			s->origin_map = map_writable(s->origin, 32); 

			if (s->target_map && s->origin_map) {
				if (init_origin_stub_x86(s) == 0) {
					atomic_inc(&s->usage);
					continue;
				}
			}
		}

		debug("Failed to initalize \"%s\" hook\n", s->name);
	}

	/* apply patches */
	stop_machine(do_init_hooks, NULL, NULL);

	return 0;
}

/* x86 dependent code */
static inline void x86_put_jmp(void * a, void * f, void * t)
{
	/* JMP opcode -- E9.xx.xx.xx.xx */

	*((char *)(a + 0)) = 0xE9;
	*(( int *)(a + 1)) = (long)(t - (f + 5));
}

#define JMP_INSN_LEN_X86	(1 + 4)

/* x86 dependent code */

static int init_origin_stub_x86(khookstr_t * s)
{
	ud_t ud;

	ud_initialize(&ud, BITS_PER_LONG, \
		      UD_VENDOR_ANY, (void *)s->target, 32);

	while (ud_disassemble(&ud) && ud.mnemonic != UD_Iret) {
		if (ud.mnemonic == UD_Ijmp || ud.mnemonic == UD_Iint3) {
			debug("It seems that \"%s\" is not a hooking virgin\n", s->name);
			return -EINVAL;
		}



		s->length += ud_insn_len(&ud);
		if (s->length >= JMP_INSN_LEN_X86) {
			memcpy(s->origin_map, s->target, s->length);
			x86_put_jmp(s->origin_map + s->length, s->origin + s->length, s->target + s->length);
			break;
		}
	}

	return 0;
}
