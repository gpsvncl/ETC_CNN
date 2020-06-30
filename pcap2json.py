import optparse
import os
import sys
from flow_analyser import Flow_Analyser

def main():
    parser = optparse.OptionParser()
    parser.add_option('-i','--input_path',action='store',dest='input_path',help='path for input files',default=None)
    parser.add_option('-o','--output_path',action='store',dest='output_path',help='path for output files',default=None)
    parser.add_option('-n','--output_name',action='store',dest='output_name',help='name for output files',default=sys.stdout)
    parser.add_option('-s','--session',action='store_true',dest='session',help='analyze based on bidirection-flow')
    parser.add_option('-m','--map',action='store_true',dest='map',help='output flow or session using xl map')

    options, args = parser.parse_args()
    input_path = options.input_path
    class_files = os.listdir(input_path)
    class_files.sort()
    for i in range(len(class_files)):
        file_abpath = os.path.join(input_path, class_files[i])
        pcap_files = os.listdir(file_abpath)
        for j in range(len(pcap_files)):
            pcap_files[j] = os.path.join(file_abpath, pcap_files[j])
        output = options.output_path + '/' + options.output_name + str(i) + '.json'
        analyser = Flow_Analyser(output=output, session=options.session, map=options.map)
        if len(pcap_files) > 0:
            analyser.extract_flow_record(pcap_files)
        else:
            print ('error: need a pcap_file')
            return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())

