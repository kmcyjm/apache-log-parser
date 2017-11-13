def matplotlib_input(list):

    original_list = [['76.97.16.122', 290], ['217.16.8.81', 161], ['222.68.77.54', 16]]

    i = 0

    l = []
    m = []

    while i < len(original_list):
        l.append(original_list[i][0])
        m.append(original_list[i][1])
        i += 1

    return ([l, m])