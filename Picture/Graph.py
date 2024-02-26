# 读取Excel文件数据绘制折线图，并保存图片至当前文件所在目录
import datetime
import xlrd
from matplotlib import pyplot as plt

# 读取Excel文件（一列一折线）
def load_data(file):
    f = xlrd.open_workbook(file)
    tables = f.sheet_names()    # 获取文件中所有工作表的名字
    # print(tables)
    table = f.sheet_by_name(tables[0])     # 通过名字获取Excel中的第一个工作表
    ncols = table.ncols     # 表格列数，nrows行数
    label_name = table.row_values(0, 0)    # 折线名
    print(label_name)
    data = []
    for i in range(ncols):
        data.append(table.col_values(i, 1))    # 第i列数据
        print(table.col_values(i, 1))
    return label_name, data

# 折线图
def draw_line_chart(data, label_name, x_label, y_label, title):
    plt.figure()
    # 两色配色：'#4d4d4d', '#B22222'
    # 三色配色：'#b3b3b3', '#4d4d4d', '#B22222'
    # 四色配色：'#B22222', '#4d4d4d', '#828282', '#b3b3b3'
    # 红黄蓝绿黑：'#B22222', '#f0bb41', '#4D85BD', '#59A95A', '#4d4d4d'
    pic_color = ['#B22222', '#4d4d4d', '#828282', '#b3b3b3']  # 折线颜色
    line_style = '-'  # '--'表示画虚线
    for i in range(len(data)):  # 第i条折线
        # print(i)
        # if data[i][0]:
        plt.plot(data[i], label=label_name[i], linestyle=line_style, color=pic_color[i])
    # plt.xlim((0, 10))  # 横坐标的数值范围
    # plt.ylim((0, 100))  # 纵坐标的数值范围
    plt.title(title)  # 图像上方的标题
    plt.xlabel(x_label)     # 标记横轴坐标名称
    plt.ylabel(y_label)     # 标记纵轴坐标名称
    plt.legend(loc='best')  # 标记标签，标签的位置自适应为best位置
    plt.grid()  # 显示网格线
    plt.savefig(title, dpi=400)   # 保存至当前文件所在目录
    # 保存图片数据至txt
    with open(title+'.txt', 'w', encoding='utf-8') as f:
        f.write("label_name = " + str(label_name) + "\n")
        f.write("x_label = " + str(x_label) + "\n")
        f.write("y_label = " + str(y_label) + "\n")
        f.write("--------data-------- \n" + str(data) + "\n")
    plt.show()

if __name__ == '__main__':
    title = "FlowEntryNumber-Background"
    x_label = "time"
    y_label = "Number"

    file = "Statistics.xls"
    label_name, data = load_data(file)
    draw_line_chart(data, label_name, x_label, y_label, title)
    
