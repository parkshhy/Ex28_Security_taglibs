import React, { Component } from 'react';
import { Tabs, Tab, Grid, Cell, Card, CardTitle, CardActions, CardMenu, IconButton, Button, CardText} from 'react-mdl';
import Port from './CSS/Portfolio.png';
import Todo from './CSS/todo.png';
import Semi from './CSS/semi.png';
import FINAL from './CSS/FINAL.png';
import SARAM from './CSS/5555.png';



class Projects extends Component {
    constructor(props) {
        super(props);
        this.state = { activeTab: 0 };

    }
    state = {
        isOpen: false
    };
  
   


    toggleCategories() {
        if (this.state.activeTab === 0) {
            return (
                <div>
                    <div className="projects-grid">

                      {/*Project1*/}
                        <Card className="box" shadow={5} style={{ minWidh: '450', margin: 'auto' }}>
                        <img src={Semi} alt="kannrisystem" style={{ height: '178px' }} />
                            <CardText>
                               図書管理システム
                            </CardText>
                            <CardActions border style={{ textAlign: "left" }}>
                                韓国 中央HTA<br />
                                プロジェクト 期間 : 2016.6~2016.7<br />
                                プロジェクト 内容 : 図書管理システム<br />
                               言語 : JAVA,JSP,ORCAL,HTML/CSS<br />
                            </CardActions>
                            <CardMenu style={{ color: '#fff' }}>
                                <IconButton name="share" />
                            </CardMenu>
                        </Card>

                        {/*Project2*/}
                        <Card className="box" shadow={5} style={{ minWidh: '450', margin: 'auto' }}>
                        <img src={FINAL} alt="kannrisystem" style={{ height: '178px' }} />
                            <CardText>
                                スポーツサイト
                            </CardText>
                            <CardActions border style={{ textAlign: "left" }}>
                            韓国 中央HTA<br />
                            プロジェクト 期間 : 2016.9~2016.10<br />
                            プロジェクト 内容 : スポーツサイト<br />
                            言語 : JAVA,MYSQL,HTML/CSS,<br />SPRING<br />
                            </CardActions>
                            <CardMenu style={{ color: '#fff' }}>
                                <IconButton name="share" />
                            </CardMenu>
                        </Card>
                    </div></div>
            )
        } else if (this.state.activeTab === 2) {
            return (
                <div>
                    <div className="projects-grid">
                        {/*docomo*/}
                        <Card className="box" shadow={5} style={{ minWidh: '450', margin: 'auto' }}>
                            <CardTitle style={{
                                color: 'black', height: '176px',
                                background: 'url(https://www.unlockjp.com/en/wp-content/uploads/2020/01/d.jpg) center / cover'
                            }}>
                            </CardTitle>
                            <CardText>
                                DOCOMO
                            </CardText>
                            <CardActions border style={{ textAlign: "left" }}>
                                勤務先 : 日本 東京 [DOCOMO]<br />
                                プロジェクト期間 : 2017.11~2018.4<br />
                               プロジェクト内容 : コンテンツ管理システム<br />
                               維持保守 テスト 業務担当<br />
                            </CardActions>
                            <CardMenu style={{ color: '#fff' }}>
                                <IconButton name="share" />
                            </CardMenu>
                        </Card>

                        {/*denso*/}
                        <Card className="box" shadow={5} style={{ minWidh: '450', margin: 'auto' }}>
                            <CardTitle style={{
                                color: 'black', height: '176px',
                                background: 'url(https://www.eetasia.com/wp-content/uploads/sites/2/images/c62d7015-fde1-4934-9993-0ccf6e27e14b.png) center / cover'
                            }}>
                            </CardTitle>
                            <CardText>
                                DENSO
                            </CardText>
                            <CardActions border style={{ textAlign: "left" }}>
                            勤務先 :日本 名古屋 [DENSO]<br />
                            プロジェクト期間 : 2018.5~2019.5<br />
                            プロジェクト内容 : 車両通信モジュール(DCM)<br />維持保守
                            テスト 業務担当<br />
                            </CardActions>
                            <CardMenu style={{ color: '#fff' }}>
                                <IconButton name="share" />
                            </CardMenu>
                        </Card>

                        {/*toyota*/}
                        <Card className="box" shadow={5} style={{ minWidh: '450', margin: 'auto' }}>
                            <CardTitle style={{
                                color: 'black', height: '176px',
                                background: 'url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAASwAAACoCAMAAABt9SM9AAAAkFBMVEX/////AAD/0dH/7+//kpL/Tk7/19f/lpb/wsL/zs7/Z2f/k5P/paX//Pz/3d3/vr7/ra3/9/f/5ub/qan/8/P/d3f/ubn/4uL/jY3/a2v/Jib/YWH/ycn/hob/fn7/oaH/MTH/W1v/cXH/LCz/Pj7/VVX/e3v/RUX/srL/ODj/GRn/DQ3/QED/m5v/S0v/Hx/qbZZMAAAJNElEQVR4nO2baVfCOhCGyyI7RRAqCogbsrn8/393TdOZTJIJ6r2eo+f6Pp8kSafpm8lkktYsAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgD/LdJK3Wq180vjpjvxqJqP21WNNsu81i8uf7tbv43KwqKXYrPOf7t4vIp8fWZnDdjFb9dvt1az3+uYEu6n/dCd/BxfXVo/j/UXXxqnJfHFjnalRP3+i6pfxT/byNzCeV1Pt3MXzF+tL/HtaVFP06W/H/KZVoTkVZS/VzHsSZeN1NRuH33LbvFj3++viv4fCy9Gg31zvWt/Qp4/oVKp4CrQ4To28xpWu56qlcbeepjvx2o7EUnK3kzVLuiAaEjK/lDXLK2fo7HyoXqAiB2nCvTwZZYYLTZNMRHW/olJxO81iJsml1LAWLQdhZdvVNalsHpjvsCaubHcMDK2kXCf7sxANr7WORORVmwu/uCgLb7XLl9UVy6+K5W7RCp/Q0Il7HgRHbsqjf/mgGNopV2hcuXYtUZzWapRoYvq7n2bDjVJHGes6C/mkWH29nqMjDWDtzrNOUdTFgAvdUO/LYt2L4k6WgO925pe3WCPjXIVf+UQXrf6dWL1UA+7EDZV0hfEpFT5SySplaP9FscZqLwJ2rolfYXprFTaj7A+wmN9hUPmUWFfpFtxPKrgWxlljWiiSWr3Hj6+JtfbK/YWI6L7XHM5tC99LRD/NRPSWmMobX55rXnj4WCw7bcUcPDaXeb5sO/Frs8oQh3IR56ioWRWcC9OrTp5313tXcPcJsVyA90NoNGEMpV+3GkEfDJfvvwei3zKWUx/r5YX+/nrYIKa0DMzHXDb2nlnM7qXrLK3Jd1TA43RbFRzigeEYVne62+43XIeq8lfXH17PlzUfTaxtrXTFs6rJ1j24EYRXopqcbg16ioP1kUOWgEQJV2LW5Vm6K2tD4nCAoh0ERwzanbIbXcskxkXqMLWpirWItAnE2sVNisqkG6I7iqf3UoV3U6+kgOtLvbr/iypVUizOr579claLxoWXnon3rLX7qp6X8Tff0IzKr/zyE2LR3KpVe77abdzGFJcxggPEO6syOX5w0SPL2jXrmN35wbUbUE0tsfNJiMUGwssOYQV5jh2oeVjNCVa4UX1MVKTFItsb7l20bypcqVTrXdcnMwudK5plYL3yjwNt3C2HJOFaulh8p1GqPYd0dvhOJga/CJsPQkN8XdMvT4vl+kQL9X3Y5NWU0g3EgkQc9tvNZvP6eIirWHmj4PErYtHy/xBfQIFjSwU04EdRyY/KaUNsaCau+4xYhTPVpT+DDeLYV9DPNE7jwn2ZBuiHBrpYZELZh7PT8QSlteDFPQRPrTfVfAnn/36+lBSL5vtK9C/YnJR9Ez48bH9SqtU0bUSginVJRrRdONVx1s4SDcnx+Rk45dZGiuoKrTQSK5emSITAK8tifxtUhEtozNZfVcsbzTINVSzyHnXqbqtK53UUQigSuMnLIUszRJf1vdKUWDRrb80Pjo3LuE03uHBcyB1lSG8XOsREvb33OJ5YlA/caVfQltMF5mHQAedGpPqtZojcwx/FhFh8D7uwvFa/Nl6jniaWodFpP0c63fZH2o5pkuywLhadG0SrjYECuthtFF4nbuIKdaAol+t5pYkrOPEb+nf0Eo9SrMRphBmaRmvZGRWjzrLVuE5NNTsN92qVKhYtI2HCWKKIxQNdIsq/Tyya4ld+M/+MoHT64MSPaPo9OyZcoZoNG7VKFYv2leolM+UKjiHByNI0vA6NUPcNT16pLhYvIjTJ+HRItipnRMJhTJ0IT9F9mXbcJ0IVa6n1hKAl3FtD+MDPj3P5KUML7dYJsagtLzlsWa6lS6+Jj/Fjt6s2IVA9tahmif7uQhWLs2slAHKk9fcavK0Zf6KxhepGWqkvFnvuakpHI5TBPYpm9nZ6Qml2+G7tNMlRX203Tj149lFSGp9Iy0RaQhvm4JxRZpIBcQYrb+2LlTjgjrQpHfAm0zAR4SLxS1LGa2XnYtDFSmxFDPT4QTyj6BTs9PgpY0N3VU3QMVWsE1p5McrGD/UtWV4LTx30ZbO0oM/ChFg86pH6vNsp9PJALN4LhCfbLl8NvFcTi895VOTBSBkNVNcyJ29u7E1er07XQWJovT4Hmzd+HRkcoLhXBoGdhFic70dd441/4AeaWGxERe7j7Cir312Zion8oTmgPcxUThVLEmJxZDr4JunQOIpmKbHq/Ey+7HTuG0UzRSx2Tx3vFLjMS4ODRndH6rVx1fRe7lmrMaSOlfk0+CgWhimvedGdUmJld/xQYkUcOl8JTxcVsTinWvQEV7yB6UbXL7KYuVDRCNdT2tgTJe34oCQllnjP0KTnEedDUSqQFEu861uRl4oXPlGUVcSitkFqy11cxKXK6lv20KYpZZKmnMIMYu09UmLJd5W1xWA0upDvEeNj16RYbrGoma8S3w3NREEci2OxWNrw8dg9PVeoJ9Syo1YOfDlB4vhutUoFrOyEWO67jxhlR5EWy3txGKAca8Ri8fFwGJF5PP300o5OvK8tp+1tIxvaeBnVzz/S6oRYWfKYUds4nRArrZYWWiKx6unWbMgvtluhfRh6qo17tdCHrmc/F9E+o3GcECuV3qiZ7ymxvJkoUPcbkVj8OUD8HDyhg/cqU7s8BU7ifSkRzkKbzh70bQ5xSqys4R29WPa6vZNiZWPl4+o3/QPAUKxkZic6796eEDaGbP2+yqj76NU0bP8SBxbR/fSHzJb+q7XaQ/RurCKxN3T3OfMNHVKxIXx83jBpljmzjaL1pXWueymX/MRDuunUZgxvH37iPZk3DfPk106XTU5Er1fpr0Hzj+xkkxcW/nDi0/NVaafJK1/b/m7ONY/uzJvJ2xb2rdNCZAJuHRbrR14d0ScODb/KMO8URaf1Dd+K58tvMvQpdjaWH/vsdywWBf/Julpr9Xdff4ourQ6zXblfpHOxUr1JcVNN4016Pvwpxjt+cbi/mp/bTUhz17/nmPB6kdze/EWW89SxxX7V+fP/iKKQF+3ZmfsO/vB63/+G/4L4nzMcj8ff838nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAH4f/wDj4Wzn1zwiCAAAAABJRU5ErkJggg==) center / cover'



                                
                            }}>

                            </CardTitle>
                            <CardText>
                                TOYOTA
                            </CardText>
                            <CardActions border style={{ textAlign: "left" }}>
                            勤務先 : 日本 名古屋 [TOYOTA]<br />
                            プロジェクト期間 : 2019.6~2019.11<br />
                            プロジェクト内容 : TOYOTA連携システム <br />維持保守 担当<br />
                              
                            </CardActions>
                            <CardMenu style={{ color: '#fff' }}>
                                <IconButton name="share" />
                            </CardMenu>
                        </Card>

                        {/*Toyata systems*/}
                        <Card className="box" shadow={5} style={{ minWidh: '450', margin: 'auto' }}>
                            <CardTitle style={{
                                color: 'black', height: '176px',
                                background: 'url(https://d3lckkmmuve1sw.cloudfront.net/attachments/0dfea67a48e300a717950687abd40afaa0b15517/store/c91aef7a3041e862f6beb3c2d6a743287364638ce00bfc8937c83c912db2/80208231.png) center / cover'
                            }}>

                            </CardTitle>
                            <CardText>
                                TOYOTA SYSTEMS
                            </CardText>
                            <CardActions border style={{ textAlign: "left" }}>
                            勤務先 : 日本 名古屋 [TOYOTA SYSTEMS]<br />
                            プロジェクト期間 : 2019.12~2020.4<br />
                            プロジェクト内容 : TOYOTA KITORA FW<br /> 維持保守 担当
                               <br />
                            </CardActions>
                            <CardMenu style={{ color: '#fff' }}>
                                <IconButton name="share" />
                            </CardMenu>
                        </Card>

                        {/*React*/}
                        <Card className="box" shadow={5} style={{ minWidh: '450', margin: 'auto' }}>
                            <CardTitle style={{
                                color: 'black', height: '176px',
                                background: 'url(https://d585tldpucybw.cloudfront.net/sfimages/default-source/blogs/templates/social/reactt-dark_1200x628.png?sfvrsn=19de8226_2) center / cover'
                            }}>
                            </CardTitle>
                            <CardText>
                                Open Sesame Tec
                            </CardText>
                            <CardActions border style={{ textAlign: "left" }}>
                            勤務先:日本 名古屋 [Open Sesame Tec]<br />
                            プロジェクト期間 : 2020.5~2020.10<br />
                            プロジェクト内容 : 車 運行管理システム 開発<br />
                               React フロントエンド 担当 <br />
                                <br />
                            </CardActions>
                            <CardMenu style={{ color: '#fff' }}>
                                <IconButton name="share" />
                            </CardMenu>
                        </Card>

                        <Card className="box" shadow={5} style={{ minWidh: '450', margin: 'auto' }}>
                        <img src={SARAM} alt="kannrisystem" style={{ height: '178px' }} />
                            <CardText>
                               Media Group
                            </CardText>
                            <CardActions border style={{ textAlign: "left" }}>
                            勤務先 : 韓国 ソウル [Media Group 人と森]<br />
                            プロジェクト期間 : 2020.12~現在<br />
                            プロジェクト内容 :  アノテーション管理システム <br />バックエンド　担当 <br />
                        
                            </CardActions>
                            <CardMenu style={{ color: '#fff' }}>
                                <IconButton name="share" />
                            </CardMenu>
                        </Card>


                    </div></div >
            )
        } else if (this.state.activeTab === 1) {
            return (
                <div>
                    <div className="projects-grid">

                        {/*Project1*/}

                        <Card className="box" shadow={5} style={{ minWidh: '450', margin: 'auto' }}>
                            <img src={Port} alt="kojinProject" style={{ height: '178px' }} />
                            <CardText>
                            React ポートフォリオ
                        </CardText>
                        <CardActions border>
                            <Button a href="https://github.com/parkshhy/123" target = "_blank">⚙️GIT HUB</Button>
                            <Button a href="https://parkshhy.github.io/123/" target = "_blank">🖥WEB PAGE</Button>
                            </CardActions>  
                        </Card>

                      {/*Project2*/}
                        <Card className="box" shadow={5} style={{ minWidh: '450', margin: 'auto' }}>
                        <img src={Todo} alt="kannrisystem" style={{ height: '178px' }} />
                            <CardText>
                                React Todo 管理システム
                        </CardText>
                     
                        <CardActions border>
                            <Button a href="https://github.com/parkshhy/todo" target = "_blank">⚙️GIT HUB</Button>
                            <Button a href="https://parkshhy.github.io/todo/" target = "_blank">🖥WEB PAGE</Button>
                        </CardActions>
                       </Card>

                         {/*Project3
                        <Card className="box" shadow={5} style={{ minWidh: '450', margin: 'auto' }}>
                        <CardTitle style={{
                                color: 'black', height: '176px',
                                background: 'url(https://www.filepicker.io/api/file/pYSVfRZFSixwoQtS1XQH) center / cover'
                            }}>
                            </CardTitle>
                            <CardText>
                                리액트 네이티브 날씨어플
                        </CardText>
                     
                        <CardActions border>
                            <Button a href="https://github.com/parkshhy/todo" target = "_blank">⚙️GIT HUB</Button>
                            <Button a href="https://parkshhy.github.io/todo/" target = "_blank">🖥WEB PAGE</Button>
                        </CardActions>
                        </Card>*/}

                  
                        </div>
                    </div>






            )
        }
    }

    render() {
        return (
            <div>
                <Tabs activeTab={this.state.activeTab}
                    onChange={(tabId => this.setState({ activeTab: tabId }))} ripple>
                    <Tab><strong>↳教育機関 プロジェクト</strong></Tab>
                    <Tab><strong>↳個人プロジェクト</strong></Tab>
                    <Tab><strong>↳経歴事項</strong></Tab>
                </Tabs>
                <Grid>
                    <Cell col={12}>
                        <div className="content">{this.toggleCategories()}</div>
                    </Cell>
                </Grid>
            </div>
        )
    }
}
export default Projects;