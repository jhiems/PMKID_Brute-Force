#!/usr/bin/env bash

#SBATCH -p wacc
#SBATCH --gres=gpu:1
#SBATCH -t 0-00:10:00
#SBATCH -J PROJECT
#SBATCH -o run.out -e run1.err



#for i in {3..9}
#do
#variables = $(echo 2^${i}| bc)
#./PMKID "`echo 2^$i | bc`" generated_big.txt 460800 
#done

./PMKID 512 generated_big.txt 46080



