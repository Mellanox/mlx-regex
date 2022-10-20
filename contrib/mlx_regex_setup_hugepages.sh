#!/bin/bash -e
# Dependency on package:
#   libhugetlbfs-utils @ CentOS
#   hugepages @ Ubuntu

# Amount of hugepage memory needed by mlx-regex daemon
min_hugemem=${MIN_HUGEMEM:-258M}

# Units of memory for mlx-regex daemon
case $(echo ${min_hugemem: -1}) in
    M)
        unit=m
        ;;
    G)
        unit=g
        ;;
    K)
        unit=k
        ;;
    *)
        echo "[ERROR]: Unsupported unit format for hugepages!"
        exit 1
        ;;
esac

# Have any hugepages been configured yet
hugetlb=$(grep Hugetlb /proc/meminfo | awk '{ print $2 }')

# Check if existing hugepages can be used or if pool needs adjusted
if [ $hugetlb -gt 0 ]; then
    if [ $unit = "k" ]; then
        required_size=${min_hugemem%?}
    elif [ $unit = "m" ]; then
	required_size=$((${min_hugemem%?} * 1024))
    elif [ $unit = "g" ]; then
	required_size=$((${min_hugemem%?} * 1024 * 1024))
    fi

    hugepagesize=$(grep Hugepagesize /proc/meminfo | awk '{ print $2 }')
    hugePages_Free=$(grep HugePages_Free /proc/meminfo | awk '{ print $2 }')

    huge_free_size=$((hugepagesize * hugePages_Free))

    if [ $huge_free_size -ge $required_size ]; then
        exit 0
    fi
fi

# Adjust the pool size
exec /usr/bin/hugeadm --pool-pages-min DEFAULT:+${min_hugemem}
