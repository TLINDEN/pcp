#include <stdio.h>
#include <sodium.h>

int main(void)
{
    printf("%d\n", sodium_version_string());
    printf("%d\n", sodium_library_version_major());
    printf("%d\n", sodium_library_version_minor());

    return 0;
}
