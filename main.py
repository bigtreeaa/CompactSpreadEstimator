import binascii
import math

from bitarray import bitarray
import matplotlib.pyplot as plt
import hashlib
import random


class MergeData:
    def __init__(self, data_path_list):
        self._data_path_list = data_path_list
        self._merged_data = []

    def merge_data(self):
        for i in range(len(self._data_path_list)):
            with open(self._data_path_list[i], 'rb+') as f:
                file = binascii.b2a_hex(f.read())
                for j in range(0, len(file), 26):
                    self._merged_data.append(file[j:j + 8] + file[j + 12:j + 20])
        return self._merged_data


class CountExactNum:
    def __init__(self, merged_data):
        self._merged_data = merged_data
        self._count_dict = {}

    def count_number(self):
        for ip in self._merged_data:
            if ip[0:8] in self._count_dict.keys():
                self._count_dict[ip[0:8]].add(ip[8:16])
            else:
                self._count_dict[ip[0:8]] = set(ip[8:16])
        return self._count_dict


class CSE:
    def __init__(self, merged_data, bit_array_len, hash_list):
        self._merged_data = merged_data
        self._bit_array_len = bit_array_len
        self._bit_array = bitarray(self._bit_array_len)
        self._bit_array.setall(0)
        self._hash_list = hash_list
        self._hash_num = len(hash_list)

    def bit_marking(self):
        for ip in self._merged_data:
            src_ip = ip[0:8]
            dst_ip = ip[8:16]
            index = int(hashlib.sha256(dst_ip).hexdigest(), 16) % self._hash_num
            self.hashM(index, src_ip)
        return self._bit_array

    def hashM(self, index, src_ip):
        position = (int(src_ip, 16) ^ self._hash_list[index]) % self._bit_array_len
        self._bit_array[position] = 1


class Plotting:
    def __init__(self, exact_count, cse_result, hash_list):
        self._exact_count = exact_count
        self._cse_result = cse_result
        self._hash_list = hash_list
        self._s = len(hash_list)
        self._m = len(cse_result)
        self._Um = cse_result.count(0)
        self._Vm = cse_result.count(0) / len(cse_result)
        self._plot_x = []
        self._plot_y = []
        self._are_list = []
        self._are_dict = {0:0, 0.5:0, 1:0, 1.5:0, 2:0, 2.5:0, 3:0, 3.5:0, 4:0, 4.5:0, 5:0, 5.5:0, 6:0}

    def plot_graph(self):
        print(len(self._exact_count.keys()))
        for src_ip in self._exact_count.keys():
            exact_value = len(self._exact_count[src_ip])
            expect_value = self.calc_num(src_ip)
            self._plot_x.append(exact_value)
            self._plot_y.append(expect_value)
            self._are_list.append(self.calc_are(exact_value, expect_value))

        plt.plot(self._plot_x, self._plot_y, 'k+')
        plt.xlabel("Actual Count")
        plt.ylabel("Compact Spread Estimator Count")
        plt.axis("square")
        plt.show()

    def are_graph(self):
        for value in self._are_list:
            if value < 0.5:
                self._are_dict[0] = self._are_dict[0]+1
            elif 0.5 <= value < 1:
                self._are_dict[0.5] = self._are_dict[0.5] + 1
            elif 1 <= value < 1.5:
                self._are_dict[1] = self._are_dict[1] + 1
            elif 1.5 <= value < 2:
                self._are_dict[1.5] = self._are_dict[1.5] + 1
            elif 2 <= value < 2.5:
                self._are_dict[2] = self._are_dict[2] + 1
            elif 2.5 <= value < 2:
                self._are_dict[2.5] = self._are_dict[2.5] + 1
            elif 3 <= value < 3.5:
                self._are_dict[3] = self._are_dict[3] + 1
            elif 3.5 <= value < 4:
                self._are_dict[3.5] = self._are_dict[3.5] + 1
            elif 4 <= value < 4.5:
                self._are_dict[4] = self._are_dict[4] + 1
            elif 4.5 <= value < 5:
                self._are_dict[4.5] = self._are_dict[4.5] + 1
            elif 5 <= value < 5.5:
                self._are_dict[5] = self._are_dict[5] + 1
            elif 5.5 <= value < 6:
                self._are_dict[5.5] = self._are_dict[5.5] + 1
            else:
                self._are_dict[6] = self._are_dict[6] + 1

        value_num = 117344
        are_x = []
        are_y = []
        for key in self._are_dict:
            are_x.append(key)
            are_y.append(self._are_dict[key]/value_num)
        for _ in range(1, len(are_y)):
            are_y[_] = are_y[_] + are_y[_-1]

        plt.xlabel("Absolute Relative Error")
        plt.ylabel("Percentage(%)")
        plt.plot(are_x, are_y, 'ks-')
        plt.show()

    def calc_num(self, src_ip):
        src_ip_0 = []
        for _ in range(self._s):
            position = (int(src_ip, 16) ^ self._hash_list[_]) % self._m
            src_ip_0.append(self._cse_result[position])
        Us = src_ip_0.count(0)
        Vs = Us / self._s
        if Vs == 0:
            k = 0
        else:
            k = self._s * math.log(1 / Vs) - self._s * math.log(1 / self._Vm)
        return k

    def calc_are(self, exact_value, expect_value):
        are = abs(expect_value - exact_value) / exact_value
        return are


if __name__ == '__main__':
    data_path_list = []
    for i in range(1, 3):
        data_path_list.append("C:\\IntrusionDetectionSystem\\IDS1\\{}".format(i))

    hash_list = []
    for i in range(500):
        hash_list.append(random.randrange(1152921504606846976, 18446744073709551616))
    bitarray_len = 3200000

    merge_data = MergeData(data_path_list)
    merged_data = merge_data.merge_data()

    count_exact_num = CountExactNum(merged_data)
    exact_num_dict = count_exact_num.count_number()

    cse = CSE(merged_data, bitarray_len, hash_list)
    cse_bitarray = cse.bit_marking()

    plotting = Plotting(exact_num_dict, cse_bitarray, hash_list)
    plotting.plot_graph()
    plotting.are_graph()
