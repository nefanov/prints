#include <linux/stop_machine.h>

/* this header includes udis86-disassembler. It should be wrapped into #ifdef x86 condition directive */
#include <udis86.h>
/*
 * Hooking structure
 */
typedef struct {
	/* tagret's name */
	char * name;

 	/* target's insn length */
	int length;

	/* target's handler address */
	void * handler;

	/* target's address and rw-mapping */
	void * target;
	void * target_map;

	/* origin's address and rw-mapping */
	void * origin;
	void * origin_map;

	atomic_t usage;
} khookstr_t;

extern khookstr_t __khook_start[], __khook_finish[];

#define khook_for_each(item)			\
	for (item = __khook_start; item < __khook_finish; item++)

/*
Здесь, name — имя перехватываемой функции (имя символа), length — длина затираемой последовательности инструкций пролога, handler — адрес функции-перехватчика, target — адрес самой целевой функции, target_map — адрес доступной для записи проекции целевой функции, origin — адрес функции-переходника, используемой для доступа к исходной функциональности, origin_map — адрес доступной для записи проекции соответствующего переходника, usage — счётчик «залипаний», учитывающий число спящих в перехвате потоков.
Каждая перехватываемая функция должна быть представлена такой структурой. Для этого, дабы упростить регистрацию перехватчиков, используется макрос DECLARE_KHOOK(...).
Вспомогательные макросы __DECLARE_TARGET_ALIAS(...), __DECLARE_TARGET_ORIGIN(...) декларируют перехватчик и переходник (32 nop'а). Саму структуру объявляет макрос __DECLARE_TARGET_STRUCT(...), посредством атрибута section определяя её в специальную секцию (.khook).
(c)
*/
#define __DECLARE_TARGET_ALIAS(t)	\
	void __attribute__((alias("khook_"#t))) khook_alias_##t(void)

#define __DECLARE_TARGET_ORIGIN(t)	\
	void notrace khook_origin_##t(void){\
		asm volatile (			\
			".rept 0x20\n"		\
			".byte 0x90\n"		\
			".endr\n"			\
		);				\
	}

#define __DECLARE_TARGET_STRUCT(t)	\
	khookstr_t __attribute__((unused,section(".khook"),aligned(1))) __khook_##t

#define DECLARE_KHOOK(t)		\
	__DECLARE_TARGET_ALIAS(t);		\
	__DECLARE_TARGET_ORIGIN(t);		\
	__DECLARE_TARGET_STRUCT(t) = {	\
		.name = #t,			\
		.handler = khook_alias_##t,	\
		.origin = khook_origin_##t,	\
		.usage = ATOMIC_INIT(0),	\
	}




