#include "fhook.h"

static int init_hooks(void)
{
	khookstr_t * s;

	khook_for_each(s) {
		s->target = get_symbol_address(s->name); // get address of symbol by func. name
		if (s->target) {
			s->target_map = map_writable(s->target, 32); // using tmp map method
			s->origin_map = map_writable(s->origin, 32); 

			if (s->target_map && s->origin_map) {
				if (init_origin_stub(s) == 0) {
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
