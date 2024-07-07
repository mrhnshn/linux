#!/bin/bash
clear

echo -e "\e[1mAbout The Script:\e[0m This script is used to find the last two digits of the ID Number from the first 9 digits."
echo -e "\n\e[1mThe Known Facts About the Turkish Identification Number:\e[0m"
echo "* The Turkish ID Number consists of 11 digits."
echo "* The actual ID number consists of the first 9 digits. The last 2 digits are a validation algorithm for these 9 digits."
echo "* The Turkish ID Number does not start with a zero."
echo "* The Turkish ID Number ends with an even digit: 0, 2, 4, 6, 8."
echo "* With the Turkish ID number algorithm, a total of 900,000,000 (Nine Hundred Million) ID numbers can be generated."

echo -e "\n\e[1mEnter ID Number\e[0m"
read -p "Enter the first 9 digits of the ID Number: " number

if [[ ! $number =~ ^[0-9]{9}$ ]]
then
  echo -e "\n| ERROR | Please enter a valid 9-digit number."
  exit 2
fi

tc1=$(($number % 10))
tc2=$((($number % 100 - $tc1) / 10))
tc3=$((($number % 1000 - $number % 100) / 100))
tc4=$((($number % 10000 - $number % 1000) / 1000))
tc5=$((($number % 100000 - $number % 10000) / 10000))
tc6=$((($number % 1000000 - $number % 100000) / 100000))
tc7=$((($number % 10000000 - $number % 1000000) / 1000000))
tc8=$((($number % 100000000 - $number % 10000000) / 10000000))
tc9=$((($number % 1000000000 - $number % 100000000) / 100000000))

tc10=$(( (7*($tc1+$tc3+$tc5+$tc7+$tc9) - ($tc2+$tc4+$tc6+$tc8)) % 10 ))
tc11=$(( ($tc1+$tc2+$tc3+$tc4+$tc5+$tc6+$tc7+$tc8+$tc9+$tc10) % 10 ))

echo -e "\nThe last 2 digits of the ID Number is: \e[1m$tc10$tc11\e[0m"
echo -e "The Whole ID Number is: \e[1m$number$tc10$tc11\e[0m\n"
