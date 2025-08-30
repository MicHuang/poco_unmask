import cupy as cp

x = cp.arange(10**6).reshape(1000, 1000)
y = cp.dot(x, x.T)  # GPU 矩阵乘法
print(y)
print(cp.cuda.runtime.getDeviceProperties(0)["name"].decode())
